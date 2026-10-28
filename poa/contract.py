"""ValidatorGovernance: the on-chain voting contract that owns the validator set.

This is a deterministic Python twin of contracts/ValidatorGovernance.sol.
It operates on a plain-dict storage so the chain can hash it into the state
root, snapshot it for reverts, and read it back when the consensus engine
needs the active validator set for a block.

Voting rules
------------
* Only current validators may propose or vote.
* A proposal either ADDs a non-validator or REMOVEs a current validator.
  At most one open proposal exists per (kind, subject).
* The proposer's yes-vote is cast automatically. Votes can be changed.
* Votes are tallied against the *current* validator set, so votes cast by a
  validator who has since been removed silently stop counting.
* A proposal passes once  yes * 100 > n * quorum_pct  and is executed in the
  same transaction. It is rejected once enough no-votes make that impossible.
* Proposals expire `vote_period` blocks after creation.
* The set can never shrink below `min_validators` or grow past `max_validators`.
"""

from __future__ import annotations

from dataclasses import dataclass, field

GOVERNANCE_ADDRESS = "0x" + "00" * 19 + "ff"

ADD, REMOVE = "ADD", "REMOVE"
PENDING, EXECUTED, REJECTED, EXPIRED, CANCELLED, FAILED = (
    "PENDING", "EXECUTED", "REJECTED", "EXPIRED", "CANCELLED", "FAILED",
)


class Revert(Exception):
    """Raised by a contract call; the chain rolls the storage back."""


@dataclass
class CallContext:
    sender: str
    block_number: int
    events: list[dict] = field(default_factory=list)

    def emit(self, name: str, **data) -> None:
        self.events.append({"event": name, **data})


def _require(cond: bool, msg: str) -> None:
    if not cond:
        raise Revert(msg)


def _is_address(value) -> bool:
    if not isinstance(value, str) or len(value) != 42 or not value.startswith("0x"):
        return False
    try:
        int(value[2:], 16)
    except ValueError:
        return False
    return True


class ValidatorGovernance:
    PUBLIC_METHODS = ("propose", "vote", "execute", "cancel")

    def __init__(self, storage: dict):
        self.s = storage

    @staticmethod
    def genesis_storage(
        validators: list[str],
        quorum_pct: int = 50,
        vote_period: int = 20,
        min_validators: int = 1,
        max_validators: int = 32,
    ) -> dict:
        if not 1 <= min_validators <= len(validators) <= max_validators:
            raise ValueError("initial validator count violates min/max bounds")
        if not 0 <= quorum_pct < 100:
            raise ValueError("quorum_pct must be in [0, 100)")
        if len(set(validators)) != len(validators):
            raise ValueError("duplicate initial validator")
        return {
            "validators": list(validators),
            "params": {
                "quorum_pct": quorum_pct,
                "vote_period": vote_period,
                "min_validators": min_validators,
                "max_validators": max_validators,
            },
            "proposals": {},
            "open": {},  # "KIND:subject" -> proposal id
            "next_id": 1,
        }

    # ---------------------------------------------------------------- views

    def get_validators(self) -> list[str]:
        return list(self.s["validators"])

    def is_validator(self, addr: str) -> bool:
        return addr in self.s["validators"]

    def required_votes(self, n: int | None = None) -> int:
        n = len(self.s["validators"]) if n is None else n
        return n * self.s["params"]["quorum_pct"] // 100 + 1

    def get_proposal(self, pid: int, block_number: int | None = None) -> dict:
        p = self.s["proposals"].get(str(pid))
        _require(p is not None, "unknown proposal")
        view = dict(p)
        if block_number is not None and self._is_expired(p, block_number):
            view["status"] = EXPIRED
        view["yes_count"], view["no_count"] = self._count(p)
        return view

    # ------------------------------------------------------------- mutating

    def call(self, ctx: CallContext, method: str, args: dict):
        _require(method in self.PUBLIC_METHODS, f"unknown method {method!r}")
        return getattr(self, method)(ctx, **args)

    def propose(self, ctx: CallContext, kind: str, subject: str) -> int:
        self._only_validator(ctx)
        _require(kind in (ADD, REMOVE), "kind must be ADD or REMOVE")
        _require(_is_address(subject), "subject is not an address")
        params = self.s["params"]
        if kind == ADD:
            _require(not self.is_validator(subject), "already a validator")
            _require(len(self.s["validators"]) < params["max_validators"], "validator set full")
        else:
            _require(self.is_validator(subject), "not a validator")
            _require(len(self.s["validators"]) > params["min_validators"], "would drop below minimum")

        key = f"{kind}:{subject}"
        if key in self.s["open"]:
            existing = self.s["proposals"][str(self.s["open"][key])]
            _require(self._is_expired(existing, ctx.block_number), "an open proposal already exists")
            self._close(existing, EXPIRED, ctx)

        pid = self.s["next_id"]
        self.s["next_id"] += 1
        self.s["proposals"][str(pid)] = {
            "id": pid,
            "kind": kind,
            "subject": subject,
            "proposer": ctx.sender,
            "created_at": ctx.block_number,
            "expires_at": ctx.block_number + params["vote_period"],
            "yes": [],
            "no": [],
            "status": PENDING,
        }
        self.s["open"][key] = pid
        ctx.emit("ProposalCreated", id=pid, kind=kind, subject=subject, proposer=ctx.sender)
        self._cast(ctx, pid, True)
        return pid

    def vote(self, ctx: CallContext, proposal_id: int, support: bool) -> str:
        self._only_validator(ctx)
        _require(isinstance(support, bool), "support must be a bool")
        return self._cast(ctx, proposal_id, support)

    def execute(self, ctx: CallContext, proposal_id: int) -> str:
        """Re-tally a proposal, e.g. after the set shrank and lowered the bar."""
        self._only_validator(ctx)
        p = self._open_proposal(ctx, proposal_id)
        return self._tally(ctx, p)

    def cancel(self, ctx: CallContext, proposal_id: int) -> str:
        p = self._open_proposal(ctx, proposal_id)
        _require(p["proposer"] == ctx.sender, "only the proposer can cancel")
        self._close(p, CANCELLED, ctx)
        return CANCELLED

    # ------------------------------------------------------------ internals

    def _only_validator(self, ctx: CallContext) -> None:
        _require(self.is_validator(ctx.sender), "caller is not a validator")

    @staticmethod
    def _is_expired(p: dict, block_number: int) -> bool:
        return p["status"] == PENDING and block_number > p["expires_at"]

    def _open_proposal(self, ctx: CallContext, pid) -> dict:
        p = self.s["proposals"].get(str(pid))
        _require(p is not None, "unknown proposal")
        _require(p["status"] == PENDING, f"proposal is {p['status']}")
        # Reverting here would also roll back an EXPIRED mark, so expiry is
        # evaluated lazily instead (same as the Solidity version).
        _require(not self._is_expired(p, ctx.block_number), "proposal expired")
        return p

    def _cast(self, ctx: CallContext, pid, support: bool) -> str:
        p = self._open_proposal(ctx, pid)
        for side in ("yes", "no"):
            if ctx.sender in p[side]:
                p[side].remove(ctx.sender)
        p["yes" if support else "no"].append(ctx.sender)
        ctx.emit("VoteCast", id=p["id"], voter=ctx.sender, support=support)
        return self._tally(ctx, p)

    def _count(self, p: dict) -> tuple[int, int]:
        active = set(self.s["validators"])
        return (sum(v in active for v in p["yes"]), sum(v in active for v in p["no"]))

    def _tally(self, ctx: CallContext, p: dict) -> str:
        n = len(self.s["validators"])
        need = self.required_votes(n)
        yes, no = self._count(p)
        if yes >= need:
            self._apply(ctx, p)
        elif n - no < need:
            self._close(p, REJECTED, ctx)
        return p["status"]

    def _apply(self, ctx: CallContext, p: dict) -> None:
        vs = self.s["validators"]
        params = self.s["params"]
        subject = p["subject"]
        # Bounds are re-checked: another proposal may have executed since this
        # one was created. A stale proposal is closed rather than reverted so
        # it can't block future proposals for the same subject.
        if p["kind"] == ADD:
            if subject in vs or len(vs) >= params["max_validators"]:
                self._close(p, FAILED, ctx)
                return
            vs.append(subject)
            ctx.emit("ValidatorAdded", validator=subject, block=ctx.block_number)
        else:
            if subject not in vs or len(vs) <= params["min_validators"]:
                self._close(p, FAILED, ctx)
                return
            # swap-and-pop, mirroring the Solidity implementation
            i = vs.index(subject)
            vs[i] = vs[-1]
            vs.pop()
            ctx.emit("ValidatorRemoved", validator=subject, block=ctx.block_number)
        self._close(p, EXECUTED, ctx)

    def _close(self, p: dict, status: str, ctx: CallContext) -> None:
        p["status"] = status
        self.s["open"].pop(f"{p['kind']}:{p['subject']}", None)
        ctx.emit("ProposalClosed", id=p["id"], status=status)
