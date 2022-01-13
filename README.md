# sn_handover

Getting Elders to agree on a single value when they hand over their propositions to the next set of Elders.

## Algo

- Elder can propose a value
- Others can vote for it
- Once the Elder has SuperMajority
- Broadcasts agreement to others
- Others vote for that agreement
- Once we have SuperMajority over that SuperMajority
- The consensus is obtained on that value
- if there are two concurrent values one of the two is deterministically chosen
- there can't be multiple handovers, generations should not change during it
