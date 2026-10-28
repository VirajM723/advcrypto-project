"""End-to-end walkthrough: validators vote a new member in, vote an offline
member out, and the consensus layer follows the contract with no restarts.

    python demo.py
"""

from poa import ADD, REMOVE, ConsensusError, ContractValidatorConsensus, Network, PrivateKey, ValidatorGovernance

NAMES = ["alice", "bob", "carol", "dave"]


def show_head(net: Network, label: str = "") -> None:
    chain = net.reference.chain
    b = chain.head
    vs = [net.name_of(v) for v in chain.validators_for(b.height)]
    print(f"  block {b.height:>2}  proposer={net.name_of(b.header['proposer']):<5} "
          f"round={b.header['round']}  seals={len(b.commit_seals)}/{len(vs)}  "
          f"set={vs} {label}")


def main() -> None:
    keys = {n: PrivateKey.from_seed(n) for n in NAMES + ["eve"]}
    genesis = ValidatorGovernance.genesis_storage(
        [keys[n].address for n in NAMES], quorum_pct=50, vote_period=10, min_validators=3)
    # eve runs a full (non-validating) node from the start
    net = Network(genesis, keys)

    print("== 1. Normal operation with 4 genesis validators")
    for _ in range(3):
        net.produce_block()
        show_head(net)

    print("\n== 2. dave goes offline: blocks still finalize (quorum 3/4), with round changes")
    net.set_online("dave", False)
    for _ in range(4):
        net.produce_block()
        show_head(net)

    print("\n== 3. Vote to ADD eve (needs 3 of 4 yes votes)")
    tx = net.send("alice", "propose", kind=ADD, subject=keys["eve"].address)
    net.produce_block(); show_head(net, "<- alice proposes (+1 yes)")
    pid = net.receipt(tx)["result"]
    net.send("bob", "vote", proposal_id=pid, support=True)
    net.produce_block(); show_head(net, "<- bob votes yes (2/3)")
    net.send("carol", "vote", proposal_id=pid, support=True)
    net.produce_block(); show_head(net, "<- carol votes yes (3/3): executed in this block")
    net.produce_block(); show_head(net, "<- eve now active, sealing")
    print("  eve's node log:", net.nodes["eve"].log)

    print("\n== 4. Vote to REMOVE offline dave (5 validators -> needs 3 yes)")
    tx = net.send("eve", "propose", kind=REMOVE, subject=keys["dave"].address)
    net.send("alice", "vote", proposal_id=pid + 1, support=True)
    net.send("bob", "vote", proposal_id=pid + 1, support=True)
    net.produce_block(); show_head(net, "<- 3 yes in one block: executed")
    for _ in range(3):
        net.produce_block()
        show_head(net, "<- no round changes: dave no longer in rotation")

    print("\n== 5. dave comes back and tries to seal a block on his own")
    net.set_online("dave", True)
    dave = net.nodes["dave"]
    try:
        dave.chain.build_block(dave.key, [], round_=0, timestamp=10**6)
    except ConsensusError as exc:
        print("  rejected:", exc)

    print("\n== 6. A fresh node replays the chain from genesis and agrees")
    fresh = ContractValidatorConsensus(genesis)
    for b in net.reference.chain.blocks[1:]:
        fresh.import_block(b)
    final = [net.name_of(v) for v in fresh.validators_for(fresh.height + 1)]
    print(f"  verified {fresh.height} blocks; head {fresh.head.hash[:16]}...; next set = {final}")
    assert fresh.head.hash == net.reference.chain.head.hash


if __name__ == "__main__":
    main()
