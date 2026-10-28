# Contract-Governed Validator Sets for PoA Consensus

A QBFT-style proof-of-authority engine whose validator set lives in a smart
contract. Validators vote on-chain to add or remove members; when a vote passes,
the consensus layer picks up the new set at the next block (or the next epoch
checkpoint). No node restarts or config edits are needed.

Pure Python 3.10+ with no dependencies. Run:

```bash
python demo.py
```

```bash
python -m unittest discover -s tests -t .
```

## Layout

| File | Role |
|---|---|
| `poa/crypto.py` | secp256k1 ECDSA (deterministic nonces, low-s), addresses, canonical hashing |
| `poa/contract.py` | `ValidatorGovernance` voting contract (Python twin of the Solidity one) |
| `poa/chain.py` | Signed transactions, blocks, state transition with revert semantics |
| `poa/consensus.py` | **The extension**: derives the validator set from contract state, then validates proposer, seals and state |
| `poa/network.py` | Multi-node simulation: round changes, offline nodes, catch-up sync |
| `contracts/ValidatorGovernance.sol` | Deployable Solidity version exposing `getValidators()` (the interface Besu QBFT reads via `validatorcontractaddress`) |

## Voting rules

- Only active validators can `propose(kind, subject)` / `vote(id, support)`. The proposer's yes vote is cast automatically, and voters can change their vote.
- A proposal passes when `yes * 100 > n * quorum_pct` (default 50, a strict majority) and executes **in the same transaction**. It is rejected as soon as enough no votes make passing impossible.
- Votes are counted against the *current* set, so votes from removed validators stop counting. If a removal lowers the bar, `execute(id)` re-tallies.
- Proposals expire after `vote_period` blocks. There is at most one open proposal per (kind, subject).
- The set is bounded by `min_validators` and `max_validators`. A proposal that passes after those bounds have changed closes as `FAILED`, so it does not block later proposals.

## How the consensus layer follows the contract

For block `h`, the validator set is `getValidators()` evaluated on the
post-state of block `checkpoint(h) = floor((h-1)/epoch) * epoch`. With
`epoch_length = 1` (the default), that is just the parent block. Each block
header commits to `validators_hash`. A block is valid only if:

1. its proposer is `sorted(set)[(h + round) % n]` and has signed the header,
2. it carries commit seals from at least `n - floor((n-1)/3)` distinct active validators (domain-separated from the proposer seal),
3. re-executing its transactions reproduces `tx_root`, `receipts_root` and `state_root`.

Because the set comes from re-executed state, a proposer can't add itself or
drop rivals. The state-root check catches that. A fresh node that replays the
chain from genesis derives the same set at every height.
`on_validator_set_change(fn)` lets node software react to changes, for
example by starting to seal once its key becomes active.
