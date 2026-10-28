"""Transactions, blocks and the state transition function."""

from __future__ import annotations

import copy
from dataclasses import dataclass, field

from .contract import GOVERNANCE_ADDRESS, CallContext, Revert, ValidatorGovernance
from .crypto import PrivateKey, Signature, hash_obj, verify


class InvalidTransaction(Exception):
    """A transaction that may not be included in a block at all."""


@dataclass
class Transaction:
    sender: str
    nonce: int
    method: str
    args: dict
    to: str = GOVERNANCE_ADDRESS
    signature: dict | None = None

    def body(self) -> dict:
        return {"sender": self.sender, "nonce": self.nonce, "to": self.to,
                "method": self.method, "args": self.args}

    @property
    def hash(self) -> str:
        return hash_obj(self.body())

    @classmethod
    def create(cls, key: PrivateKey, nonce: int, method: str, **args) -> "Transaction":
        tx = cls(key.address, nonce, method, args)
        tx.signature = key.sign(tx.hash).to_dict()
        return tx

    def check_signature(self) -> None:
        if self.signature is None:
            raise InvalidTransaction("unsigned transaction")
        sig = Signature.from_dict(self.signature)
        if sig.signer != self.sender or not verify(self.hash, sig):
            raise InvalidTransaction("bad transaction signature")

    def to_dict(self) -> dict:
        return {**self.body(), "signature": self.signature}


@dataclass
class Block:
    header: dict
    transactions: list[Transaction]
    proposer_seal: dict | None = None
    commit_seals: list[dict] = field(default_factory=list)

    @property
    def hash(self) -> str:
        return hash_obj(self.header)

    @property
    def height(self) -> int:
        return self.header["height"]

    @property
    def commit_digest(self) -> str:
        # Domain-separated from the proposer seal so one can't be replayed as the other.
        return hash_obj({"commit": self.hash})


def new_state(genesis_storage: dict) -> dict:
    return {"nonces": {}, "contracts": {GOVERNANCE_ADDRESS: genesis_storage}}


def state_root(state: dict) -> str:
    return hash_obj(state)


def governance(state: dict) -> ValidatorGovernance:
    return ValidatorGovernance(state["contracts"][GOVERNANCE_ADDRESS])


def apply_transaction(state: dict, tx: Transaction, block_number: int) -> dict:
    """Mutates `state`; returns a receipt. Raises InvalidTransaction if the tx
    must not be in a block. A contract revert is *not* invalid: the nonce is
    consumed and the receipt records failure, as on Ethereum."""
    tx.check_signature()
    if tx.to != GOVERNANCE_ADDRESS:
        raise InvalidTransaction("unknown destination")
    expected = state["nonces"].get(tx.sender, 0)
    if tx.nonce != expected:
        raise InvalidTransaction(f"bad nonce: expected {expected}, got {tx.nonce}")
    state["nonces"][tx.sender] = expected + 1

    storage = state["contracts"][GOVERNANCE_ADDRESS]
    snapshot = copy.deepcopy(storage)
    ctx = CallContext(sender=tx.sender, block_number=block_number)
    try:
        result = ValidatorGovernance(storage).call(ctx, tx.method, tx.args)
        return {"tx": tx.hash, "status": 1, "result": result, "events": ctx.events}
    except (Revert, TypeError) as exc:  # TypeError: malformed call arguments
        state["contracts"][GOVERNANCE_ADDRESS] = snapshot
        return {"tx": tx.hash, "status": 0, "error": str(exc), "events": []}
