use rand::{
    prelude::{IteratorRandom, StdRng},
    Rng, SeedableRng,
};

mod net;
use net::{DummyProposal, Net, Packet};

use std::collections::BTreeSet;
use quickcheck::TestResult;
use quickcheck_macros::quickcheck;
use test_env_log::test;

use sn_handover::{Ballot, Error, HandoverState, Proposal, PublicKey, SecretKey, SignedVote, Vote};

#[test]
fn test_reject_changing_reconfig_when_one_is_in_progress() -> Result<(), Error> {
    let mut rng = StdRng::from_seed([0u8; 32]);
    let mut proc = HandoverState::random(&mut rng, Default::default());
    proc.force_join(proc.public_key());
    proc.propose(DummyProposal(rng.gen()))?;
    assert!(matches!(
        proc.propose(DummyProposal(rng.gen())),
        Err(Error::ExistingVoteIncompatibleWithNewVote { .. })
    ));
    Ok(())
}

#[test]
fn test_reject_vote_from_non_member() -> Result<(), Error> {
    let mut rng = StdRng::from_seed([0u8; 32]);
    let mut net = Net::with_procs(2, &mut rng);
    let p0 = net.procs[0].public_key();
    let p1 = net.procs[1].public_key();
    net.force_join(p1, p0);
    net.force_join(p1, p1);

    let resp = net.procs[1].propose(DummyProposal(rng.gen()))?;
    net.enqueue_packets(resp.into_iter().map(|vote_msg| Packet {
        source: p1,
        vote_msg,
    }));
    net.drain_queued_packets()?;
    Ok(())
}

#[test]
fn test_handle_vote_rejects_packet_from_bad_gen() {
    let mut rng = StdRng::from_seed([0u8; 32]);
    let mut net = Net::with_procs(2, &mut rng);
    let a_0 = net.procs[0].public_key();
    let a_1 = net.procs[1].public_key();
    net.procs[0].force_join(a_0);
    net.procs[0].force_join(a_1);
    net.procs[1].force_join(a_0);
    net.procs[1].force_join(a_1);
    net.procs[1].gen = 1; // invalid gen

    let packets = net.procs[0]
        .propose(DummyProposal(rng.gen()))
        .unwrap()
        .into_iter()
        .map(|vote_msg| Packet {
            source: a_0,
            vote_msg,
        })
        .collect::<Vec<_>>();

    net.procs[1].votes = Default::default();

    assert_eq!(packets.len(), 2); // two members in the network

    net.enqueue_packets(packets);
    let res = net.drain_queued_packets();

    assert!(matches!(
        res,
        Err(Error::VoteWithInvalidGeneration {
            vote_gen: 0,
            gen: 1,
        })
    ));
}

#[test]
fn test_reject_votes_with_invalid_signatures() -> Result<(), Error> {
    let mut rng = StdRng::from_seed([0u8; 32]);
    let mut proc = HandoverState::random(&mut rng, Default::default());
    let ballot = Ballot::Propose(DummyProposal(rng.gen()));
    let gen = proc.gen + 1;
    let voter = PublicKey::random(&mut rng);
    let bytes = bincode::serialize(&(&ballot, &gen))?;
    let sig = SecretKey::random(&mut rng).sign(&bytes);
    let vote = Vote { gen, ballot };
    let resp = proc.handle_signed_vote(SignedVote { vote, voter, sig });

    #[cfg(feature = "blsttc")]
    assert!(matches!(resp, Err(Error::Blsttc(_))));

    #[cfg(feature = "ed25519")]
    assert!(matches!(resp, Err(Error::Ed25519(_))));

    #[cfg(feature = "bad_crypto")]
    assert!(matches!(resp, Err(Error::BadCrypto(_))));
    Ok(())
}

#[test]
fn test_split_vote() -> eyre::Result<()> {
    let mut rng = StdRng::from_seed([0u8; 32]);
    for nprocs in 1..7 {
        println!("[TEST] testing with {} voters", nprocs);

        // make network of nprocs voters
        let mut net = Net::with_procs(nprocs, &mut rng);
        for i in 0..nprocs {
            let i_actor = net.procs[i].public_key();
            for j in 0..(nprocs) {
                net.procs[j].force_join(i_actor);
            }
        }

        // make each voter propose a different thing
        for i in 0..nprocs {
            let a_i = net.procs[i].public_key();
            let packets = net.procs[i]
                .propose(DummyProposal(i as u64))?
                .into_iter()
                .map(|vote_msg| Packet {
                    source: a_i,
                    vote_msg,
                });
            println!("[TEST] voter {} voted {}", i, i);
            net.enqueue_packets(packets);
        }
        net.drain_queued_packets()?;

        // make voters notice split and vote for merge votes
        for i in 0..nprocs {
            for j in 0..nprocs {
                net.enqueue_anti_entropy(i, j);
            }
        }
        net.drain_queued_packets()?;

        // make sure they all reach the same conclusion
        let first_voters_value = net.procs[0].consensus;
        for i in 0..nprocs {
            println!("[TEST] checking voter {}'s consensus value: {:?}", i, net.procs[i].consensus);
            assert_eq!(net.procs[i].consensus, first_voters_value);
        }
    }

    Ok(())
}

#[test]
fn test_round_robin_split_vote() -> eyre::Result<()> {
    let mut rng = StdRng::from_seed([0u8; 32]);
    for nprocs in 1..7 {
        println!("[TEST] testing with {} voters", nprocs);

        // make network of nprocs voters
        let mut net = Net::with_procs(nprocs, &mut rng);
        for i in 0..nprocs {
            let i_actor = net.procs[i].public_key();
            for j in 0..(nprocs) {
                net.procs[j].force_join(i_actor);
            }
        }

        // make each voter propose a different thing
        for i in 0..nprocs {
            let a_i = net.procs[i].public_key();
            let packets = net.procs[i]
                .propose(DummyProposal(i as u64))?
                .into_iter()
                .map(|vote_msg| Packet {
                    source: a_i,
                    vote_msg,
                });
            println!("[TEST] voter {} voted {}", i, i);
            net.enqueue_packets(packets);
        }

        // send all the votes before letting others react
        while !net.packets.is_empty() {
            for i in 0..net.procs.len() {
                net.deliver_packet_from_source(net.procs[i].public_key())?;
            }
        }

        // make users notice split and vote for merge
        for i in 0..nprocs {
            for j in 0..nprocs {
                net.enqueue_anti_entropy(i, j);
            }
        }
        net.drain_queued_packets()?;

        // generate msc file
        net.generate_msc(&format!("round_robin_split_vote_{}.msc", nprocs))?;

        // make sure they all reach the same conclusion
        let max_proposed_value = nprocs-1;
        let expected_consensus_value = Some(DummyProposal(max_proposed_value as u64));
        for i in 0..nprocs {
            println!("[TEST] checking voter {}'s consensus value: {:?}", i, net.procs[i].consensus);
            assert_eq!(net.procs[i].consensus, expected_consensus_value);
        }
    }
    Ok(())
}

#[test]
fn test_simple_proposal() {
    let mut rng = StdRng::from_seed([0u8; 32]);
    let mut net = Net::with_procs(4, &mut rng);
    for i in 0..4 {
        let a_i = net.procs[i].public_key();
        for j in 0..4 {
            let a_j = net.procs[j].public_key();
            net.force_join(a_i, a_j);
        }
    }
    let proc_0 = net.procs[0].public_key();
    let packets = net.procs[0]
        .propose(DummyProposal(3))
        .unwrap()
        .into_iter()
        .map(|vote_msg| Packet {
            source: proc_0,
            vote_msg,
        });
    net.enqueue_packets(packets);
    net.drain_queued_packets().unwrap();

    net.generate_msc("simple_join.msc").unwrap();

    // make sure they all reach the same conclusion
    let first_voters_value = net.procs[0].consensus;
    for i in 0..4 {
        println!("[TEST] checking voter {}'s consensus value: {:?}", i, net.procs[i].consensus);
        assert_eq!(net.procs[i].consensus, first_voters_value);
    }
}

// #[quickcheck]
// fn prop_validate_proposal(
//     join_or_leave: bool,
//     actor_idx: u8,
//     members: u8,
//     seed: u128,
// ) -> Result<TestResult, Error> {
//     let mut seed_buf = [0u8; 32];
//     seed_buf[0..16].copy_from_slice(&seed.to_le_bytes());
//     let mut rng = StdRng::from_seed(seed_buf);
//
//     if members >= 7 {
//         return Ok(TestResult::discard());
//     }
//
//     let mut proc = HandoverState::<DummyProposal>::random(&mut rng, Default::default());
//
//     let trusted_actors: Vec<_> = (0..members)
//         .map(|_| PublicKey::random(&mut rng))
//         .chain(vec![proc.public_key()])
//         .collect();
//
//     for a in trusted_actors.iter().copied() {
//         proc.force_join(a);
//     }
//
//     let all_actors = {
//         let mut actors = trusted_actors;
//         actors.push(PublicKey::random(&mut rng));
//         actors
//     };
//
//     let actor = all_actors[actor_idx as usize % all_actors.len()];
//     let proposal = match join_or_leave {
//         true => DummyProposal(1),
//         false => DummyProposal(0),
//     };
//
//     assert!(proposal.validate().is_ok());
//     Ok(TestResult::passed())
// }
//
// #[quickcheck]
// fn prop_bft_consensus(
//     recursion_limit: u8,
//     n: u8,
//     faulty: Vec<u8>,
//     seed: u128,
// ) -> Result<TestResult, Error> {
//     let n = n % 6 + 1;
//     let recursion_limit = recursion_limit % (n / 2).max(1);
//     let faulty = BTreeSet::from_iter(
//         faulty
//             .into_iter()
//             .map(|p| p % n)
//             .filter(|p| p != &0) // genesis can not be faulty
//             .take((n / 3) as usize),
//     );
//     // All non-faulty nodes eventually decide on a proposal
//
//     let mut seed_buf = [0u8; 32];
//     seed_buf[0..16].copy_from_slice(&seed.to_le_bytes());
//     let mut rng = rand::rngs::StdRng::from_seed(seed_buf);
//
//     let mut net = Net::with_procs(n as usize, &mut rng);
//
//     // Set first proc as genesis
//     let genesis = net.procs[0].public_key();
//     for p in net.procs.iter_mut() {
//         p.force_join(genesis);
//     }
//
//     let faulty = BTreeSet::from_iter(
//         faulty
//             .into_iter()
//             .map(|idx| net.procs[idx as usize].public_key()),
//     );
//     let n_actions = rng.gen::<u8>() % 3;
//
//     for _ in 0..n_actions {
//         match rng.gen::<u8>() % 3 {
//             0 if !faulty.is_empty() => {
//                 match rng.gen::<bool>() {
//                     true => {
//                         // send a randomized packet
//                         let packet = net.gen_faulty_packet(recursion_limit, &faulty, &mut rng);
//                         net.enqueue_packets(vec![packet]);
//                     }
//                     false => {
//                         // drop a random packet
//                         let source = net.gen_public_key(&mut rng);
//                         net.drop_packet_from_source(source);
//                     }
//                 };
//             }
//             1 => {
//                 // node takes honest action
//                 let pks = BTreeSet::from_iter(net.procs.iter().map(HandoverState::public_key));
//
//                 let proc = if let Some(proc) = net
//                     .procs
//                     .iter_mut()
//                     .filter(|p| !faulty.contains(&p.public_key())) // filter out faulty nodes
//                     .filter(|p| p.voters.contains(&p.public_key())) // filter out non-members
//                     .choose(&mut rng)
//                 {
//                     proc
//                 } else {
//                     // No honest node can take an action
//                     continue;
//                 };
//
//                 let source = proc.public_key();
//
//                 let proposal = match rng.gen::<bool>() {
//                     true => DummyProposal(1),
//                     false => DummyProposal(0),
//                 };
//
//                 let packets = Vec::from_iter(
//                     proc.propose(proposal)
//                         .unwrap()
//                         .into_iter()
//                         .map(|vote_msg| Packet { source, vote_msg }),
//                 );
//                 net.enqueue_packets(packets);
//             }
//             _ => {
//                 // Network delivers a packet
//                 let source = net.gen_public_key(&mut rng);
//                 let _ = net.deliver_packet_from_source(source);
//             }
//         };
//     }
//
//     let _ = net.drain_queued_packets();
//
//     let honest_procs = Vec::from_iter(
//         net.procs
//             .iter()
//             .filter(|p| !faulty.contains(&p.public_key())),
//     );
//
//     // BFT TERMINATION PROPERTY: all honest procs have decided ==>
//     for p in honest_procs.iter() {
//         assert_eq!(p.votes, Default::default());
//     }
//
//     // BFT AGREEMENT PROPERTY: all honest procs have decided on the same values
//     let reference_proc = &honest_procs[0];
//     for p in honest_procs.iter() {
//         assert_eq!(reference_proc.gen, p.gen);
//         for g in 0..=reference_proc.gen {
//             assert_eq!(reference_proc.voters.clone(), p.voters.clone())
//         }
//     }
//
//     Ok(TestResult::passed())
// }
