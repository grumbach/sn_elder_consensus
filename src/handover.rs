use crate::vote::*;
use std::collections::{BTreeMap, BTreeSet};

use rand::{CryptoRng, Rng};
use serde::{Deserialize, Serialize};

use crate::{Error, Proposal, PublicKey, Result, SecretKey};
use core::fmt::Debug;
use log::info;

/// A local state each elder keeps
/// Contains their view of the current votes
/// assuming all votes from same generation (self.gen)
/// assuming no churn so no generation or voters change during consensus vote
#[derive(Debug)]
pub struct HandoverState<T>
where
    T: Ord,
{
    pub secret_key: SecretKey,
    pub gen: Generation, // section state unique id based on sn_membership
    pub votes: BTreeMap<PublicKey, SignedVote<T>>, // the votes we collected
    pub voters: BTreeSet<PublicKey>, // current elders
    pub consensus: Option<T>, // proposition elders agreed on in the end
}

impl<'de, T> HandoverState<T>
where
    T: Clone + Copy + Debug + Ord + PartialEq + Serialize + Deserialize<'de> + Proposal,
{
    pub fn from(
        secret_key: SecretKey,
        gen: Generation,
        voters: BTreeSet<PublicKey>,
    ) -> HandoverState<T> {
        HandoverState {
            secret_key,
            gen,
            votes: Default::default(),
            voters,
            consensus: None,
        }
    }

    pub fn random(mut rng: impl Rng + CryptoRng, voters: BTreeSet<PublicKey>) -> HandoverState<T> {
        HandoverState {
            secret_key: SecretKey::random(&mut rng),
            gen: Default::default(),
            votes: Default::default(),
            voters,
            consensus: None,
        }
    }

    pub fn public_key(&self) -> PublicKey {
        self.secret_key.public_key()
    }

    pub fn propose(&mut self, proposition: T) -> Result<Vec<VoteMsg<T>>> {
        let vote = Vote {
            gen: self.gen,
            ballot: Ballot::Propose(proposition),
        };
        let signed_vote = self.sign_vote(vote)?;
        self.validate_signed_vote(&signed_vote)?;
        self.cast_vote(signed_vote)
    }

    pub fn save_reached_consensus(&mut self, consensus: Option<T>) {
        self.consensus = consensus;
    }

    pub fn force_join(&mut self, public_key: PublicKey) {
        self.voters.insert(public_key);
    }

    // Tell an actor our view of the current votes
    pub fn anti_entropy(&self, actor: PublicKey) -> Vec<VoteMsg<T>> {
        info!(
            "[MBR] anti-entropy for {:?} from {:?}",
            actor,
            self.public_key()
        );

        self.votes
            .values()
            .cloned()
            .map(|v| self.send(v, actor))
            .collect()
    }

    pub fn handle_signed_vote(&mut self, signed_vote: SignedVote<T>) -> Result<Vec<VoteMsg<T>>> {
        // if consensus was reached, ignore the vote and send them the consensus proof (all the votes)
        if self.consensus.is_some() {
            return Ok(self.anti_entropy(signed_vote.voter));
        }

        // validate and store
        self.validate_signed_vote(&signed_vote)?;
        self.save_signed_vote(&signed_vote);

        // if we have a split vote
        // report a Merge vote, elders will vote for this Merge as they see it,
        // once we have super majority over that Merge, elders vote for SuperMajority over that Merge
        // as everyone signed that SuperMajority over Merge, we have super majority over super majority
        // everyone can just use resolve_votes to get the determined winner proposal
        if self.is_split_vote(&self.votes.values().cloned().collect()) {
            info!("[MBR] Detected split vote");
            let merge_vote = Vote {
                gen: self.gen,
                ballot: Ballot::Merge(self.votes.values().cloned().collect()).simplify(),
            };
            let signed_merge_vote = self.sign_vote(merge_vote)?;

            if let Some(our_vote) = self.votes.get(&self.public_key()) {
                let proposals_we_voted_for =
                    BTreeSet::from_iter(our_vote.proposals().into_iter().map(|(_, p)| p));
                let proposals_we_would_vote_for: BTreeSet<_> = signed_merge_vote
                    .proposals()
                    .into_iter()
                    .map(|(_, r)| r)
                    .collect();

                if proposals_we_voted_for == proposals_we_would_vote_for {
                    info!("[MBR] This vote didn't add new information, waiting for more votes...");
                    return Ok(vec![]);
                }
            }

            info!("[MBR] Either we haven't voted or our previous vote didn't fully overlap, merge them.");
            return self.cast_vote(signed_merge_vote);
        }

        // super majority over a SuperMajority vote means elders reached consensus
        if self.is_super_majority_over_super_majorities(&self.votes.values().cloned().collect()) {
            self.save_reached_consensus(
                self.resolve_votes(&self.votes.values().cloned().collect()),
            );
            info!("[MBR] Detected super majority over super majorities");
            return Ok(vec![]);
        }

        // once we reach super majority, we need to vote for it show others we've seen it
        // by voting for it in a SuperMajority vote
        if self.is_super_majority(&self.votes.values().cloned().collect()) {
            info!("[MBR] Detected super majority");

            if let Some(our_vote) = self.votes.get(&self.public_key()) {
                // We voted during this generation.

                // We may have committed to some proposals that is not part of this super majority.
                // This happens when the network was able to form super majority without our vote.
                // We can not change our vote since all we know is that a subset of the network saw
                // super majority. It could still be the case that two disjoint subsets of the network
                // see different super majorities, this case will be resolved by the split vote detection
                // as more messages are delivered.

                let super_majority_proposal =
                    self.resolve_votes(&self.votes.values().cloned().collect());

                let we_have_comitted_to_proposals_not_in_super_majority =
                    if let Some(p) = super_majority_proposal {
                        self.resolve_votes(&our_vote.unpack_votes().into_iter().cloned().collect())
                            .into_iter()
                            .any(|r| p != r)
                    } else {
                        false
                    };

                if we_have_comitted_to_proposals_not_in_super_majority {
                    info!("[MBR] We have committed to proposals that the super majority has not seen, waiting till we either have a split vote or SM/SM");
                    return Ok(vec![]);
                } else if our_vote.vote.is_super_majority_ballot() {
                    info!("[MBR] We've already sent a super majority, waiting till we either have a split vote or SM / SM");
                    return Ok(vec![]);
                }
            }

            info!("[MBR] broadcasting super majority");
            let ballot = Ballot::SuperMajority(self.votes.values().cloned().collect()).simplify();
            let vote = Vote {
                gen: self.gen,
                ballot,
            };
            let signed_vote = self.sign_vote(vote)?;
            return self.cast_vote(signed_vote);
        }

        // We have determined that we don't yet have enough votes to take action.
        // If we have not yet voted, this is where we would contribute our vote
        if !self.votes.contains_key(&self.public_key()) {
            let signed_vote = self.sign_vote(Vote {
                gen: self.gen,
                ballot: signed_vote.vote.ballot,
            })?;
            return self.cast_vote(signed_vote);
        }

        Ok(vec![])
    }

    pub fn sign_vote(&self, vote: Vote<T>) -> Result<SignedVote<T>> {
        Ok(SignedVote {
            voter: self.public_key(),
            sig: self.secret_key.sign(&vote.to_bytes()?),
            vote,
        })
    }

    fn cast_vote(&mut self, signed_vote: SignedVote<T>) -> Result<Vec<VoteMsg<T>>> {
        self.save_signed_vote(&signed_vote);
        self.broadcast(signed_vote)
    }

    fn save_signed_vote(&mut self, signed_vote: &SignedVote<T>) {
        for vote in signed_vote.unpack_votes() {
            let existing_vote = self.votes.entry(vote.voter).or_insert_with(|| vote.clone());
            if vote.supersedes(existing_vote) {
                *existing_vote = vote.clone()
            }
        }
    }

    fn count_votes(&self, votes: &BTreeSet<SignedVote<T>>) -> BTreeMap<BTreeSet<T>, usize> {
        let mut count: BTreeMap<BTreeSet<T>, usize> = Default::default();

        for vote in votes.iter() {
            let proposals =
                BTreeSet::from_iter(vote.proposals().into_iter().map(|(_, proposal)| proposal));
            let c = count.entry(proposals).or_default();
            *c += 1;
        }

        count
    }

    // When voters voted for different proposals and super majority can't be obtained anymore we have a split vote
    // Assuming we have 7 voters if 3 voters voted for A and 4 voters for B, we have a split vote because neither A or B can ever reach super majority (5)
    fn is_split_vote(&self, votes: &BTreeSet<SignedVote<T>>) -> bool {
        let counts = self.count_votes(votes);
        let most_votes = counts.values().max().cloned().unwrap_or_default();
        let members_count = self.voters.len();
        let voters = BTreeSet::from_iter(votes.iter().map(|v| v.voter));
        let remaining_voters = self.voters.difference(&voters).count();

        // give the remaining votes to the proposals with the most votes.
        let predicted_votes = most_votes + remaining_voters;

        3 * voters.len() > 2 * members_count && 3 * predicted_votes <= 2 * members_count
    }

    fn is_super_majority(&self, votes: &BTreeSet<SignedVote<T>>) -> bool {
        let most_votes = self
            .count_votes(votes)
            .values()
            .max()
            .cloned()
            .unwrap_or_default();
        let n = self.voters.len();

        3 * most_votes > 2 * n
    }

    fn is_super_majority_over_super_majorities(&self, votes: &BTreeSet<SignedVote<T>>) -> bool {
        let (winning_proposals, _) = self
            .count_votes(votes)
            .into_iter()
            .max_by_key(|(_, count)| *count)
            .unwrap_or_default();

        let count_of_super_majorities = votes
            .iter()
            .filter(|v| {
                BTreeSet::from_iter(v.proposals().into_iter().map(|(_, r)| r)) == winning_proposals
            })
            .filter(|v| v.vote.is_super_majority_ballot())
            .count();

        3 * count_of_super_majorities > 2 * self.voters.len()
    }

    fn resolve_votes(&self, votes: &BTreeSet<SignedVote<T>>) -> Option<T> {
        let (winning_proposals, _) = self
            .count_votes(votes)
            .into_iter()
            .max_by_key(|(_, count)| *count)
            .unwrap_or_default();

        // we need to choose one deterministically
        // proposals are comparable because they impl Ord so we arbitrarily pick the max
        winning_proposals.into_iter().max()
    }

    fn validate_is_member(&self, public_key: PublicKey) -> Result<()> {
        if !self.voters.contains(&public_key) {
            Err(Error::NonMember {
                public_key,
                members: self.voters.clone(),
            })
        } else {
            Ok(())
        }
    }

    fn validate_vote_supersedes_existing_vote(&self, signed_vote: &SignedVote<T>) -> Result<()> {
        if self.votes.contains_key(&signed_vote.voter)
            && !signed_vote.supersedes(&self.votes[&signed_vote.voter])
            && !self.votes[&signed_vote.voter].supersedes(signed_vote)
        {
            Err(Error::ExistingVoteIncompatibleWithNewVote {
                existing_vote: format!("{:?}", self.votes[&signed_vote.voter]),
            })
        } else {
            Ok(())
        }
    }

    fn validate_voters_have_not_changed_proposals(
        &self,
        signed_vote: &SignedVote<T>,
    ) -> Result<()> {
        // Ensure that nobody is trying to change their proposal proposals.
        let proposals: BTreeSet<(PublicKey, T)> = self
            .votes
            .values()
            .flat_map(|v| v.proposals())
            .chain(signed_vote.proposals())
            .collect();

        let voters = BTreeSet::from_iter(proposals.iter().map(|(actor, _)| actor));
        if voters.len() != proposals.len() {
            Err(Error::VoterChangedMind {
                proposal: proposals
                    .into_iter()
                    .map(|(pk, p)| (pk, format!("{:?}", p)))
                    .collect(),
            })
        } else {
            Ok(())
        }
    }

    pub fn validate_signed_vote(&self, signed_vote: &SignedVote<T>) -> Result<()> {
        signed_vote.validate_signature()?;
        self.validate_vote(&signed_vote.vote)?;
        self.validate_is_member(signed_vote.voter)?;
        self.validate_vote_supersedes_existing_vote(signed_vote)?;
        self.validate_voters_have_not_changed_proposals(signed_vote)?;
        Ok(())
    }

    fn validate_vote(&self, vote: &Vote<T>) -> Result<()> {
        if vote.gen != self.gen {
            return Err(Error::VoteWithInvalidGeneration {
                vote_gen: vote.gen,
                gen: self.gen,
            });
        }

        match &vote.ballot {
            Ballot::Propose(proposal) => proposal.validate(),
            Ballot::Merge(votes) => {
                for child_vote in votes.iter() {
                    if child_vote.vote.gen != vote.gen {
                        return Err(Error::MergedVotesMustBeFromSameGen {
                            child_gen: child_vote.vote.gen,
                            merge_gen: vote.gen,
                        });
                    }
                    self.validate_signed_vote(child_vote)?;
                }
                Ok(())
            }
            Ballot::SuperMajority(votes) => {
                if !self.is_super_majority(
                    &votes
                        .iter()
                        .flat_map(SignedVote::unpack_votes)
                        .cloned()
                        .collect(),
                ) {
                    Err(Error::SuperMajorityBallotIsNotSuperMajority {
                        ballot: format!("{:?}", vote.ballot),
                        members: self.voters.clone(),
                    })
                } else {
                    for child_vote in votes.iter() {
                        if child_vote.vote.gen != vote.gen {
                            return Err(Error::MergedVotesMustBeFromSameGen {
                                child_gen: child_vote.vote.gen,
                                merge_gen: vote.gen,
                            });
                        }
                        self.validate_signed_vote(child_vote)?;
                    }
                    Ok(())
                }
            }
        }
    }

    fn broadcast(&self, signed_vote: SignedVote<T>) -> Result<Vec<VoteMsg<T>>> {
        Ok(self
            .voters
            .iter()
            .cloned()
            .map(|member| self.send(signed_vote.clone(), member))
            .collect())
    }

    fn send(&self, vote: SignedVote<T>, dest: PublicKey) -> VoteMsg<T> {
        VoteMsg { vote, dest }
    }
}
