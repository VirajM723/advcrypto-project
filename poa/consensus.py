"""Contract-driven validator-set consensus extension.

The engine is a QBFT-style proof-of-authority protocol: a round-robin
proposer seals each block and a block is final once it carries commit seals
from a BFT quorum (n - f, f = floor((n-1)/3)) of the active validators.

What makes it an *extension* is where the validator set comes from. It is
never stored in the consensus layer: for every block it is read from the
ValidatorGovernance contract's storage in the parent state (or the latest
epoch checkpoint). A vote that executes in block h therefore changes who may
propose and seal from block h+1 onward, with no node restarts or config
edits, and every node derives the same set by re-executing the chain.
"""

from __future__ import annotations

import copy
from typing import Callable

from .chain import (Block, InvalidTransaction, Transaction, apply_transaction,
                    governance, new_state, state_root)
from .crypto import PrivateKey, Signature, hash_obj, verify


class ConsensusError(Exception):
    pass


def bft_quorum(n: int) -> int:
    return n - (n - 1) // 3


SetChangeListener = Callable[[int, list[str], list[str]], None]


class ContractValidatorConsensus:
    """One node's replica of the chain plus the consensus rules over it."""

    def __init__(self, genesis_storage: dict, epoch_length: int = 1, genesis_time: int = 0):
        if epoch_length < 1:
            raise ValueError("epoch_length must be >= 1")
        self.epoch_length = epoch_length
        state = new_state(copy.deepcopy(genesis_storage))
        genesis = Block(
            header={"height": 0, "parent_hash": "0" * 64, "timestamp": genesis_time,
                    "proposer": None, "round": 0, "tx_root": hash_obj([]),
                    "receipts_root": hash_obj([]), "state_root": state_root(state),
                    "validators_hash": hash_obj(sorted(governance(state).get_validators()))},
            transactions=[],
        )
        self.blocks: list[Block] = [genesis]
        self.states: list[dict] = [state]  # states[h] = state after block h
        self.receipts: list[list[dict]] = [[]]
        self._listeners: list[SetChangeListener] = []

    # -------------------------------------------------- validator selection

    @property
    def head(self) -> Block:
        return self.blocks[-1]

    @property
    def height(self) -> int:
        return self.head.height

    def checkpoint_for(self, height: int) -> int:
        """Height whose post-state defines the validator set for `height`.
        With epoch_length=1 this is simply the parent block."""
        return (height - 1) // self.epoch_length * self.epoch_length

    def validators_for(self, height: int) -> list[str]:
        checkpoint = self.checkpoint_for(height)
        if height < 1 or checkpoint > self.height:
            raise ValueError(f"no validator set known yet for height {height}")
        state = self.states[checkpoint]
        # Sorted so proposer rotation doesn't depend on the contract's storage order.
        return sorted(governance(state).get_validators())

    def proposer_for(self, height: int, round_: int) -> str:
        vs = self.validators_for(height)
        return vs[(height + round_) % len(vs)]

    def quorum_for(self, height: int) -> int:
        return bft_quorum(len(self.validators_for(height)))

    def on_validator_set_change(self, fn: SetChangeListener) -> None:
        """fn(effective_height, added, removed) fires when an imported block
        makes a different validator set active for the following block."""
        self._listeners.append(fn)

    # ------------------------------------------------------------- proposing

    def build_block(self, key: PrivateKey, txs: list[Transaction], round_: int,
                    timestamp: int) -> Block:
        height = self.height + 1
        if self.proposer_for(height, round_) != key.address:
            raise ConsensusError(f"{key.address} is not the proposer for height {height} round {round_}")
        state = copy.deepcopy(self.states[-1])
        included, receipts = [], []
        for tx in txs:
            try:
                receipts.append(apply_transaction(state, tx, height))
                included.append(tx)
            except InvalidTransaction:
                continue  # drop it, as a mempool would
        block = Block(
            header={
                "height": height,
                "parent_hash": self.head.hash,
                "timestamp": timestamp,
                "proposer": key.address,
                "round": round_,
                "tx_root": hash_obj([t.hash for t in included]),
                "receipts_root": hash_obj(receipts),
                "state_root": state_root(state),
                "validators_hash": hash_obj(self.validators_for(height)),
            },
            transactions=included,
        )
        block.proposer_seal = key.sign(block.hash).to_dict()
        return block

    def commit_seal(self, key: PrivateKey, block: Block) -> dict:
        """Validate then countersign a proposed block (the COMMIT message)."""
        self.validate_block(block, require_commits=False)
        if key.address not in self.validators_for(block.height):
            raise ConsensusError("only active validators can commit")
        return key.sign(block.commit_digest).to_dict()

    # ------------------------------------------------------------ validation

    def validate_block(self, block: Block, require_commits: bool = True):
        """Full validation against this replica's head. Returns the resulting
        (state, receipts) so import doesn't re-execute."""
        h = block.header
        height = self.height + 1
        if h.get("height") != height:
            raise ConsensusError(f"expected height {height}, got {h.get('height')}")
        if h["parent_hash"] != self.head.hash:
            raise ConsensusError("parent hash mismatch")
        if h["timestamp"] <= self.head.header["timestamp"]:
            raise ConsensusError("timestamp not increasing")

        validators = self.validators_for(height)
        if h["validators_hash"] != hash_obj(validators):
            raise ConsensusError("validators_hash does not match contract-derived set")
        if not isinstance(h["round"], int) or h["round"] < 0:
            raise ConsensusError("bad round")
        expected = self.proposer_for(height, h["round"])
        if h["proposer"] != expected:
            raise ConsensusError(f"wrong proposer: expected {expected}, got {h['proposer']}")
        if block.proposer_seal is None:
            raise ConsensusError("missing proposer seal")
        seal = Signature.from_dict(block.proposer_seal)
        if seal.signer != h["proposer"] or not verify(block.hash, seal):
            raise ConsensusError("bad proposer seal")

        if require_commits:
            self._check_commits(block, validators)

        if h["tx_root"] != hash_obj([t.hash for t in block.transactions]):
            raise ConsensusError("tx_root mismatch")
        state = copy.deepcopy(self.states[-1])
        receipts = []
        for tx in block.transactions:
            try:
                receipts.append(apply_transaction(state, tx, height))
            except InvalidTransaction as exc:
                raise ConsensusError(f"block contains invalid tx: {exc}") from exc
        if h["receipts_root"] != hash_obj(receipts):
            raise ConsensusError("receipts_root mismatch")
        if h["state_root"] != state_root(state):
            raise ConsensusError("state_root mismatch")
        return state, receipts

    def _check_commits(self, block: Block, validators: list[str]) -> None:
        active = set(validators)
        signers = set()
        for raw in block.commit_seals:
            sig = Signature.from_dict(raw)
            signer = sig.signer
            if signer not in active:
                raise ConsensusError(f"commit seal from non-validator {signer}")
            if signer in signers:
                raise ConsensusError(f"duplicate commit seal from {signer}")
            if not verify(block.commit_digest, sig):
                raise ConsensusError(f"bad commit seal from {signer}")
            signers.add(signer)
        need = bft_quorum(len(validators))
        if len(signers) < need:
            raise ConsensusError(f"insufficient commit seals: {len(signers)}/{need}")

    def import_block(self, block: Block) -> list[dict]:
        state, receipts = self.validate_block(block)
        before = self.validators_for(block.height)
        self.blocks.append(block)
        self.states.append(state)
        self.receipts.append(receipts)
        after = self.validators_for(block.height + 1)
        if before != after:
            added = sorted(set(after) - set(before))
            removed = sorted(set(before) - set(after))
            for fn in self._listeners:
                fn(block.height + 1, added, removed)
        return receipts

    # ---------------------------------------------------------------- helpers

    def governance_view(self):
        return governance(self.states[-1])

    def nonce_of(self, addr: str) -> int:
        return self.states[-1]["nonces"].get(addr, 0)
