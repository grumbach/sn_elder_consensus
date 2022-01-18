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

## Testing

Enabling the `bad_crypto` feature for tests will make them hundreds of times faster!
`bad_crypto` is a mock for cryptographic ops, don't use it in production!

```
cargo test --no-default-features --features bad_crypto  -- --nocapture
```
