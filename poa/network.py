"""In-process network simulation: independent node replicas, a shared
mempool, round changes when a proposer is down, and catch-up sync."""

from __future__ import annotations

from dataclasses import dataclass, field

from .chain import Block, Transaction
from .consensus import ConsensusError, ContractValidatorConsensus
from .crypto import PrivateKey


class LivenessFailure(Exception):
    pass


@dataclass
class Node:
    name: str
    key: PrivateKey
    chain: ContractValidatorConsensus
    online: bool = True
    log: list[str] = field(default_factory=list)

    @property
    def address(self) -> str:
        return self.key.address

    @property
    def is_active_validator(self) -> bool:
        return self.address in self.chain.validators_for(self.chain.height + 1)


class Network:
    def __init__(self, genesis_storage: dict, keys: dict[str, PrivateKey], epoch_length: int = 1):
        self.genesis_storage = genesis_storage
        self.epoch_length = epoch_length
        self.nodes: dict[str, Node] = {}
        self.mempool: list[Transaction] = []
        self.clock = 0
        for name, key in keys.items():
            self.add_node(name, key)

    def add_node(self, name: str, key: PrivateKey) -> Node:
        node = Node(name, key, ContractValidatorConsensus(self.genesis_storage, self.epoch_length))
        node.chain.on_validator_set_change(
            lambda h, added, removed, n=node: n.log.append(
                f"validator set changes at block {h}: +{added} -{removed}"))
        self.nodes[name] = node
        if self.reference is not node:
            self.sync(node)
        return node

    @property
    def reference(self) -> Node:
        """The online node with the longest chain."""
        online = [n for n in self.nodes.values() if n.online]
        return max(online, key=lambda n: n.chain.height)

    def name_of(self, address: str) -> str:
        for n in self.nodes.values():
            if n.address == address:
                return n.name
        return address

    # ------------------------------------------------------------ clients

    def send(self, name: str, method: str, **args) -> Transaction:
        node = self.nodes[name]
        pending = sum(tx.sender == node.address for tx in self.mempool)
        tx = Transaction.create(node.key, self.reference.chain.nonce_of(node.address) + pending,
                                method, **args)
        self.mempool.append(tx)
        return tx

    def receipt(self, tx: Transaction) -> dict | None:
        for receipts in self.reference.chain.receipts:
            for r in receipts:
                if r["tx"] == tx.hash:
                    return r
        return None

    # ---------------------------------------------------------- consensus

    def produce_block(self) -> Block:
        """Run one height of consensus, changing rounds past offline proposers."""
        ref = self.reference.chain
        height = ref.height + 1
        validators = ref.validators_for(height)
        by_addr = {n.address: n for n in self.nodes.values()}
        self.clock += 1
        for round_ in range(len(validators)):
            proposer = by_addr.get(ref.proposer_for(height, round_))
            if proposer is None or not proposer.online:
                continue  # round-change timeout
            self.sync(proposer)
            block = proposer.chain.build_block(proposer.key, list(self.mempool), round_, self.clock)
            seals = []
            for addr in validators:
                node = by_addr.get(addr)
                if node is None or not node.online:
                    continue
                self.sync(node)
                try:
                    seals.append(node.chain.commit_seal(node.key, block))
                except ConsensusError as exc:
                    node.log.append(f"refused to commit block {height}: {exc}")
            if len(seals) < ref.quorum_for(height):
                continue
            block.commit_seals = seals
            online = [n for n in self.nodes.values() if n.online]
            for node in online:
                self.sync(node)
            for node in online:
                node.chain.import_block(block)
            included = {t.hash for t in block.transactions}
            self.mempool = [t for t in self.mempool if t.hash not in included
                            and t.nonce >= ref.nonce_of(t.sender)]
            return block
        raise LivenessFailure(f"no round reached quorum at height {height}")

    def run(self, blocks: int) -> list[Block]:
        return [self.produce_block() for _ in range(blocks)]

    def sync(self, node: Node) -> None:
        """Catch a lagging node up by fully validating every missing block."""
        src = self.reference.chain
        while node.chain.height < src.height:
            node.chain.import_block(src.blocks[node.chain.height + 1])

    def set_online(self, name: str, online: bool) -> None:
        self.nodes[name].online = online
        if online:
            self.sync(self.nodes[name])

