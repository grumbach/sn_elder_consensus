use core::fmt::Debug;
use serde::{Deserialize, Serialize};

pub trait Proposal<'de, T>
where
    T: Clone + Copy + PartialEq + Eq + PartialOrd + Ord + Serialize + Deserialize<'de> + Debug,
{
}
