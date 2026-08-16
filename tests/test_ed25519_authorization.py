#!/usr/bin/env python3
from __future__ import annotations

import unittest

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    HAS_CRYPTO=True
except ImportError:
    Ed25519PrivateKey=None; HAS_CRYPTO=False

from semantic_gate.authorization import AuthorizationError,Ed25519AuthorizationAuthority,Ed25519AuthorizationVerifier


def claims(**changes):
    value={"authorization_id":"auth_example","issuer":"gate","audience":"orders-broker","request_id":"req_example","request_hash":"r"*64,"requester":"example-agent","assurance":"ask","action":"order.place","target":"orders.place","parameters":{"sku":"example-sku"},"parameters_hash":"","policy_hash":"p"*64,"approval_evidence_ids":["approval_example"],"approval_provenance":{"approval_example":{"transport":"test"}},"issued_at":100,"expires_at":200,"nonce":"n"*32,"execution_enabled":True,"simulation_only":False}
    value.update(changes); return value


@unittest.skipUnless(HAS_CRYPTO,"install semantic-gate[approvals]")
class Ed25519AuthorizationTests(unittest.TestCase):
    def test_private_signer_and_public_only_verifier_are_separate(self):
        private=Ed25519PrivateKey.generate(); signer=Ed25519AuthorizationAuthority(private,issuer="gate")
        verifier=Ed25519AuthorizationVerifier(private.public_key(),issuer="gate")
        token=signer.issue(claims(issuer="gate"))
        self.assertEqual("order.place",verifier.verify(token,audience="orders-broker",now=100)["action"])
        self.assertFalse(hasattr(verifier,"issue"))
        tampered=dict(token); tampered["action"]="order.other"
        with self.assertRaises(AuthorizationError): verifier.verify(tampered,audience="orders-broker",now=100)


if __name__=="__main__": unittest.main()
