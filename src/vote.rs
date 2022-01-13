use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::{PublicKey, Result, Signature};

use core::fmt::Debug;

/// Probably use id based on sn_membership's member history
/// This generation ensures all elders are on the same page regarding section membership
/// Accepting members must be blocked when brb consensus happens so that generations can't change during this consensus time
pub type Generation = u64;

/// A ballot with:
/// - a proposition vote, all elders that agree on it vote for that proposal
/// - a merge ballot to inform other elders that there is a split
/// - a supermajority over supermajority vote, when a proposition has super majority of votes
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Ballot<T>
where
    T: Ord,
{
    Propose(T),
    Merge(BTreeSet<SignedVote<T>>),
    SuperMajority(BTreeSet<SignedVote<T>>),
}

impl<T> std::fmt::Debug for Ballot<T>
where
    T: Debug + Ord,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Ballot::Propose(r) => write!(f, "P({:?})", r),
            Ballot::Merge(votes) => write!(f, "M{:?}", votes),
            Ballot::SuperMajority(votes) => write!(f, "SM{:?}", votes),
        }
    }
}

impl<'de, T> Ballot<T>
where
    T: Clone + Copy + Ord + Serialize + Deserialize<'de> + Debug,
{
    fn simplify_votes(signed_votes: &BTreeSet<SignedVote<T>>) -> BTreeSet<SignedVote<T>> {
        let mut simpler_votes = BTreeSet::new();
        for v in signed_votes.iter() {
            let this_vote_is_superseded = signed_votes
                .iter()
                .filter(|other_v| other_v != &v)
                .any(|other_v| other_v.supersedes(v));

            if !this_vote_is_superseded {
                simpler_votes.insert(v.clone());
            }
        }
        simpler_votes
    }

    pub fn simplify(&self) -> Self {
        match &self {
            Ballot::Propose(_) => self.clone(), // already in simplest form
            Ballot::Merge(votes) => Ballot::Merge(Self::simplify_votes(votes)),
            Ballot::SuperMajority(votes) => Ballot::SuperMajority(Self::simplify_votes(votes)),
        }
    }
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Vote<T>
where
    T: Ord,
{
    pub gen: Generation,
    pub ballot: Ballot<T>,
}

impl<T> Debug for Vote<T>
where
    T: Ord + Debug,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "G{}-{:?}", self.gen, self.ballot)
    }
}

impl<'de, T> Vote<T>
where
    T: Clone + Copy + PartialEq + Eq + PartialOrd + Ord + Debug + Serialize + Deserialize<'de>,
{
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        Ok(bincode::serialize(&(&self.ballot, &self.gen))?)
    }

    pub fn is_super_majority_ballot(&self) -> bool {
        matches!(self.ballot, Ballot::SuperMajority(_))
    }
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct SignedVote<T>
where
    T: Ord,
{
    pub vote: Vote<T>,
    pub voter: PublicKey,
    pub sig: Signature,
}

impl<T> Debug for SignedVote<T>
where
    T: Ord + Debug,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}@{}", self.vote, self.voter)
    }
}

impl<'de, T> SignedVote<T>
where
    T: Clone + Copy + Debug + Ord + Serialize + Deserialize<'de>,
{
    pub fn validate_signature(&self) -> Result<()> {
        Ok(self.voter.verify(&self.vote.to_bytes()?, &self.sig)?)
    }

    pub fn unpack_votes(&self) -> BTreeSet<&Self> {
        match &self.vote.ballot {
            Ballot::Propose(_) => BTreeSet::from_iter([self]),
            Ballot::Merge(votes) | Ballot::SuperMajority(votes) => BTreeSet::from_iter(
                std::iter::once(self).chain(votes.iter().flat_map(Self::unpack_votes)),
            ),
        }
    }

    pub fn proposals(&self) -> BTreeSet<(PublicKey, T)> {
        match &self.vote.ballot {
            Ballot::Propose(prop) => BTreeSet::from_iter([(self.voter, *prop)]),
            Ballot::Merge(votes) | Ballot::SuperMajority(votes) => {
                BTreeSet::from_iter(votes.iter().flat_map(Self::proposals))
            }
        }
    }

    pub fn supersedes(&self, signed_vote: &SignedVote<T>) -> bool {
        if self == signed_vote {
            true
        } else {
            match &self.vote.ballot {
                Ballot::Propose(_) => false,
                Ballot::Merge(votes) | Ballot::SuperMajority(votes) => {
                    votes.iter().any(|v| v.supersedes(signed_vote))
                }
            }
        }
    }
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Debug)]
pub struct VoteMsg<T>
where
    T: Ord,
{
    pub vote: SignedVote<T>,
    pub dest: PublicKey,
}
