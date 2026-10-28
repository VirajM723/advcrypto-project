import copy
import unittest

from poa import (ADD, REMOVE, ConsensusError, ContractValidatorConsensus, LivenessFailure,
                 Network, PrivateKey, Transaction, ValidatorGovernance, bft_quorum)
from poa.contract import CallContext, Revert
from poa.crypto import Signature, hash_obj, verify

NAMES = ["alice", "bob", "carol", "dave"]
KEYS = {n: PrivateKey.from_seed(n) for n in NAMES + ["eve", "frank"]}
ADDR = {n: k.address for n, k in KEYS.items()}


def make_net(names=NAMES, extra=("eve",), epoch_length=1, **params):
    params.setdefault("min_validators", 2)
    genesis = ValidatorGovernance.genesis_storage([ADDR[n] for n in names], **params)
    keys = {n: KEYS[n] for n in list(names) + list(extra)}
    return Network(genesis, keys, epoch_length=epoch_length), genesis


def active(net):
    chain = net.reference.chain
    return chain.validators_for(chain.height + 1)


class CryptoTests(unittest.TestCase):
    def test_sign_verify_and_tamper(self):
        k = KEYS["alice"]
        d = hash_obj("msg")
        sig = k.sign(d)
        self.assertTrue(verify(d, sig))
        self.assertEqual(sig.signer, k.address)
        self.assertFalse(verify(hash_obj("other"), sig))
        self.assertFalse(verify(d, Signature(sig.r, sig.s, KEYS["bob"].pubkey)))

    def test_high_s_rejected(self):
        from poa.crypto import N
        d = hash_obj("x")
        sig = KEYS["alice"].sign(d)
        self.assertFalse(verify(d, Signature(sig.r, N - sig.s, sig.pubkey)))


class ContractTests(unittest.TestCase):
    def setUp(self):
        self.storage = ValidatorGovernance.genesis_storage(
            [ADDR[n] for n in NAMES], quorum_pct=50, vote_period=5, min_validators=3)
        self.c = ValidatorGovernance(self.storage)

    def call(self, who, method, block=1, **args):
        return self.c.call(CallContext(ADDR[who], block), method, args)

    def test_majority_adds(self):
        self.assertEqual(self.c.required_votes(), 3)
        pid = self.call("alice", "propose", kind=ADD, subject=ADDR["eve"])
        self.assertEqual(self.call("bob", "vote", proposal_id=pid, support=True), "PENDING")
        self.assertEqual(self.call("carol", "vote", proposal_id=pid, support=True), "EXECUTED")
        self.assertIn(ADDR["eve"], self.c.get_validators())

    def test_rejection_when_pass_impossible(self):
        pid = self.call("alice", "propose", kind=ADD, subject=ADDR["eve"])
        self.call("bob", "vote", proposal_id=pid, support=False)
        self.assertEqual(self.call("carol", "vote", proposal_id=pid, support=False), "REJECTED")
        # a fresh proposal for the same subject is allowed after rejection
        self.call("alice", "propose", kind=ADD, subject=ADDR["eve"])

    def test_vote_change(self):
        pid = self.call("alice", "propose", kind=ADD, subject=ADDR["eve"])
        self.call("bob", "vote", proposal_id=pid, support=False)
        self.call("bob", "vote", proposal_id=pid, support=True)
        p = self.c.get_proposal(pid)
        self.assertEqual((p["yes_count"], p["no_count"]), (2, 0))

    def test_access_control_and_bounds(self):
        with self.assertRaisesRegex(Revert, "not a validator"):
            self.call("eve", "propose", kind=ADD, subject=ADDR["frank"])
        with self.assertRaisesRegex(Revert, "already a validator"):
            self.call("alice", "propose", kind=ADD, subject=ADDR["bob"])
        with self.assertRaisesRegex(Revert, "not a validator"):
            self.call("alice", "propose", kind=REMOVE, subject=ADDR["eve"])
        pid = self.call("alice", "propose", kind=REMOVE, subject=ADDR["dave"])
        with self.assertRaisesRegex(Revert, "already exists"):
            self.call("bob", "propose", kind=REMOVE, subject=ADDR["dave"])
        self.call("bob", "vote", proposal_id=pid, support=True)
        self.call("carol", "vote", proposal_id=pid, support=True)
        self.assertEqual(len(self.c.get_validators()), 3)
        with self.assertRaisesRegex(Revert, "below minimum"):
            self.call("alice", "propose", kind=REMOVE, subject=ADDR["bob"])

    def test_expiry(self):
        pid = self.call("alice", "propose", kind=ADD, subject=ADDR["eve"], block=1)
        self.assertEqual(self.c.get_proposal(pid, block_number=7)["status"], "EXPIRED")
        with self.assertRaisesRegex(Revert, "expired"):
            self.call("bob", "vote", proposal_id=pid, support=True, block=7)
        # an expired proposal no longer blocks a new one
        new = self.call("bob", "propose", kind=ADD, subject=ADDR["eve"], block=7)
        self.assertNotEqual(new, pid)

    def test_votes_of_removed_validators_stop_counting(self):
        add = self.call("dave", "propose", kind=ADD, subject=ADDR["eve"])
        rm = self.call("alice", "propose", kind=REMOVE, subject=ADDR["dave"])
        self.call("bob", "vote", proposal_id=rm, support=True)
        self.call("carol", "vote", proposal_id=rm, support=True)
        self.assertNotIn(ADDR["dave"], self.c.get_validators())
        p = self.c.get_proposal(add)
        self.assertEqual(p["yes_count"], 0)  # dave's yes vote no longer counts
        self.assertEqual(self.c.required_votes(), 2)

    def test_execute_after_set_shrinks(self):
        # 4 validators need 3; after a removal 3 need 2, so 2 standing yes votes suffice
        add = self.call("alice", "propose", kind=ADD, subject=ADDR["eve"])
        self.call("bob", "vote", proposal_id=add, support=True)
        rm = self.call("carol", "propose", kind=REMOVE, subject=ADDR["dave"])
        self.call("alice", "vote", proposal_id=rm, support=True)
        self.call("bob", "vote", proposal_id=rm, support=True)
        self.assertEqual(self.call("carol", "execute", proposal_id=add), "EXECUTED")

    def test_stale_proposal_fails_instead_of_blocking(self):
        storage = ValidatorGovernance.genesis_storage(
            [ADDR[n] for n in NAMES], quorum_pct=50, min_validators=1, max_validators=5)
        self.c = ValidatorGovernance(storage)
        a = self.call("alice", "propose", kind=ADD, subject=ADDR["eve"])
        b = self.call("alice", "propose", kind=ADD, subject=ADDR["frank"])
        for v in ("bob", "carol"):
            self.call(v, "vote", proposal_id=a, support=True)
        self.call("bob", "vote", proposal_id=b, support=True)
        # set is now full (5); frank's proposal passes the vote but can't apply
        self.assertEqual(self.call("carol", "vote", proposal_id=b, support=True), "FAILED")
        with self.assertRaisesRegex(Revert, "FAILED"):
            self.call("dave", "vote", proposal_id=b, support=True)
        self.assertNotIn(f"ADD:{ADDR['frank']}", storage["open"])
        self.assertEqual(len(self.c.get_validators()), 5)


class ConsensusTests(unittest.TestCase):
    def test_bft_quorum(self):
        self.assertEqual([bft_quorum(n) for n in (1, 2, 3, 4, 5, 7)], [1, 2, 3, 3, 4, 5])

    def test_addition_activates_next_block(self):
        net, _ = make_net()
        tx = net.send("alice", "propose", kind=ADD, subject=ADDR["eve"])
        net.send("bob", "vote", proposal_id=1, support=True)
        net.send("carol", "vote", proposal_id=1, support=True)
        block = net.produce_block()
        self.assertEqual(net.receipt(tx)["status"], 1)
        chain = net.reference.chain
        self.assertNotIn(ADDR["eve"], chain.validators_for(block.height))
        self.assertIn(ADDR["eve"], chain.validators_for(block.height + 1))
        self.assertTrue(net.nodes["eve"].is_active_validator)
        # eve participates within one full rotation
        blocks = net.run(5)
        self.assertIn(ADDR["eve"], {b.header["proposer"] for b in blocks})
        signers = {Signature.from_dict(s).signer for s in blocks[0].commit_seals}
        self.assertIn(ADDR["eve"], signers)

    def test_removal_excludes_proposer_and_seals(self):
        net, _ = make_net()
        net.send("alice", "propose", kind=REMOVE, subject=ADDR["dave"])
        net.send("bob", "vote", proposal_id=1, support=True)
        net.send("carol", "vote", proposal_id=1, support=True)
        net.produce_block()
        self.assertNotIn(ADDR["dave"], active(net))
        for b in net.run(4):
            self.assertNotEqual(b.header["proposer"], ADDR["dave"])
            signers = {Signature.from_dict(s).signer for s in b.commit_seals}
            self.assertNotIn(ADDR["dave"], signers)

    def test_removed_validator_seal_rejected(self):
        net, _ = make_net()
        net.send("alice", "propose", kind=REMOVE, subject=ADDR["dave"])
        net.send("bob", "vote", proposal_id=1, support=True)
        net.send("carol", "vote", proposal_id=1, support=True)
        net.produce_block()
        chain = net.nodes["alice"].chain
        proposer = net.nodes[net.name_of(chain.proposer_for(chain.height + 1, 0))]
        block = proposer.chain.build_block(proposer.key, [], 0, net.clock + 1)
        block.commit_seals = [KEYS[n].sign(block.commit_digest).to_dict()
                              for n in ("alice", "bob", "dave")]
        with self.assertRaisesRegex(ConsensusError, "non-validator"):
            chain.validate_block(block)

    def test_offline_validator_voted_out_restores_rotation(self):
        net, _ = make_net(NAMES + ["eve"], extra=())
        net.set_online("dave", False)
        net.set_online("eve", False)
        # 5 validators, 2 down: quorum is 4 -> chain halts
        with self.assertRaises(LivenessFailure):
            net.produce_block()
        # dave returns; with 4 online, the remaining 3 vote eve out
        net.set_online("dave", True)
        net.send("alice", "propose", kind=REMOVE, subject=ADDR["eve"])
        net.send("bob", "vote", proposal_id=1, support=True)
        net.send("carol", "vote", proposal_id=1, support=True)
        net.produce_block()
        self.assertNotIn(ADDR["eve"], active(net))
        self.assertTrue(all(b.header["round"] == 0 for b in net.run(4)))

    def test_epoch_delayed_activation(self):
        net, _ = make_net(epoch_length=5)
        net.send("alice", "propose", kind=ADD, subject=ADDR["eve"])
        net.send("bob", "vote", proposal_id=1, support=True)
        net.send("carol", "vote", proposal_id=1, support=True)
        net.produce_block()  # executed at block 1
        chain = net.reference.chain
        for h in range(2, 6):
            self.assertNotIn(ADDR["eve"], chain.validators_for(h))
        net.run(4)  # reach checkpoint block 5
        self.assertIn(ADDR["eve"], chain.validators_for(6))

    def test_fresh_node_replays_identically(self):
        net, genesis = make_net()
        net.send("alice", "propose", kind=ADD, subject=ADDR["eve"])
        net.send("bob", "vote", proposal_id=1, support=True)
        net.send("carol", "vote", proposal_id=1, support=True)
        net.run(3)
        changes = []
        fresh = ContractValidatorConsensus(genesis)
        fresh.on_validator_set_change(lambda h, a, r: changes.append((h, a, r)))
        for b in net.reference.chain.blocks[1:]:
            fresh.import_block(b)
        self.assertEqual(fresh.head.hash, net.reference.chain.head.hash)
        self.assertEqual(changes, [(2, [ADDR["eve"]], [])])

    def test_non_validator_votes_revert_on_chain(self):
        net, _ = make_net()
        tx = net.send("eve", "propose", kind=ADD, subject=ADDR["frank"])
        net.produce_block()
        r = net.receipt(tx)
        self.assertEqual(r["status"], 0)
        self.assertIn("not a validator", r["error"])
        self.assertEqual(active(net), sorted(ADDR[n] for n in NAMES))


class BlockValidationTests(unittest.TestCase):
    def setUp(self):
        self.net, _ = make_net()
        self.net.send("alice", "propose", kind=ADD, subject=ADDR["eve"])
        self.chain = self.net.nodes["alice"].chain
        h = self.chain.height + 1
        self.proposer = self.net.nodes[self.net.name_of(self.chain.proposer_for(h, 0))]
        self.block = self.proposer.chain.build_block(
            self.proposer.key, list(self.net.mempool), 0, 1)
        self.block.commit_seals = [KEYS[n].sign(self.block.commit_digest).to_dict() for n in NAMES]

    def resign(self, block, key=None):
        block.proposer_seal = (key or self.proposer.key).sign(block.hash).to_dict()
        block.commit_seals = [KEYS[n].sign(block.commit_digest).to_dict() for n in NAMES]
        return block

    def test_valid_block_imports(self):
        self.chain.import_block(self.block)
        self.assertEqual(self.chain.height, 1)

    def test_wrong_proposer(self):
        b = copy.deepcopy(self.block)
        other = next(n for n in NAMES if ADDR[n] != self.proposer.address)
        b.header["proposer"] = ADDR[other]
        self.resign(b, KEYS[other])
        with self.assertRaisesRegex(ConsensusError, "wrong proposer"):
            self.chain.validate_block(b)

    def test_outsider_cannot_propose(self):
        b = copy.deepcopy(self.block)
        b.header["proposer"] = ADDR["eve"]
        self.resign(b, KEYS["eve"])
        with self.assertRaisesRegex(ConsensusError, "wrong proposer"):
            self.chain.validate_block(b)

    def test_insufficient_seals(self):
        self.block.commit_seals = self.block.commit_seals[:2]
        with self.assertRaisesRegex(ConsensusError, "insufficient"):
            self.chain.validate_block(self.block)

    def test_duplicate_seals(self):
        self.block.commit_seals = self.block.commit_seals[:2] + self.block.commit_seals[:1]
        with self.assertRaisesRegex(ConsensusError, "duplicate"):
            self.chain.validate_block(self.block)

    def test_proposer_seal_not_reusable_as_commit(self):
        self.block.commit_seals = [KEYS[n].sign(self.block.hash).to_dict() for n in NAMES]
        with self.assertRaisesRegex(ConsensusError, "bad commit seal"):
            self.chain.validate_block(self.block)

    def test_forged_validator_set(self):
        b = copy.deepcopy(self.block)
        b.header["validators_hash"] = hash_obj(sorted(ADDR[n] for n in NAMES + ["eve"]))
        self.resign(b)
        with self.assertRaisesRegex(ConsensusError, "validators_hash"):
            self.chain.validate_block(b)

    def test_forged_state_root(self):
        # A malicious proposer can't write itself into the contract storage.
        b = copy.deepcopy(self.block)
        b.header["state_root"] = "00" * 32
        self.resign(b)
        with self.assertRaisesRegex(ConsensusError, "state_root"):
            self.chain.validate_block(b)

    def test_tampered_transaction(self):
        b = copy.deepcopy(self.block)
        b.transactions[0].args["subject"] = ADDR["frank"]
        b.header["tx_root"] = hash_obj([t.hash for t in b.transactions])
        self.resign(b)
        with self.assertRaisesRegex(ConsensusError, "invalid tx"):
            self.chain.validate_block(b)

    def test_replayed_transaction(self):
        self.chain.import_block(self.block)
        replay = Transaction(**{k: v for k, v in self.block.transactions[0].to_dict().items()})
        h = self.chain.height + 1
        p = self.net.nodes[self.net.name_of(self.chain.proposer_for(h, 0))]
        b = self.chain.build_block(p.key, [], 0, 2)
        b.transactions = [replay]
        b.header["tx_root"] = hash_obj([replay.hash])
        b.proposer_seal = p.key.sign(b.hash).to_dict()
        b.commit_seals = [KEYS[n].sign(b.commit_digest).to_dict() for n in NAMES]
        with self.assertRaisesRegex(ConsensusError, "bad nonce"):
            self.chain.validate_block(b)


if __name__ == "__main__":
    unittest.main()
