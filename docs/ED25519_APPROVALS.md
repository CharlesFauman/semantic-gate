# Ed25519 human approvals

Install the optional cryptography extra:

```sh
python -m pip install 'semantic-gate[approvals]'
```

`Ed25519ApprovalRoster` enrolls human public keys with an exact actor and allowed assurance levels. Display names, notifier keys, service identities and caller-supplied signer labels are not authority.

## Roster

```json
{
  "keys": {
    "owner-2026": {
      "actor": "human:owner",
      "public_key": "<base64 raw Ed25519 public key>",
      "assurances": ["ask", "step_up"]
    }
  }
}
```

Keep private keys outside the repository. Sign an exact unsigned decision from a file:

```json
{
  "evidence_id":"human-event-2026-08-16-001",
  "request_id":"req_example",
  "request_hash":"<request hash from the pending request>",
  "actor":"human:owner",
  "decision":"approve",
  "assurance":"step_up",
  "key_id":"owner-2026",
  "signed_at":1786920000,
  "expires_at":1786920300
}
```

```sh
semantic-gate-sign-approval \
  --decision decision.json \
  --private-key /secure/path/owner-ed25519.pem \
  --output signed-decision.json
```

The private key path is passed, never key material. The signature binds evidence ID, request ID/hash, enrolled actor, decision, assurance, key ID, signing time and expiry.

Run the complete local example after installing the extra:

```sh
python examples/integrations/ed25519_approval_flow.py
```

That script generates a temporary Ed25519 key, constructs a real roster and
`CoreBackend`, signs an exact decision, invokes `SignedApprovalBridge`, and
asserts that the resulting authorization retains the human event ID. In a
deployed host, load the signer output before calling the same bridge:

```python
import json
from pathlib import Path
from semantic_gate import Ed25519ApprovalRoster, SignedApprovalBridge

signed_decision = json.loads(Path("signed-decision.json").read_text())
roster = Ed25519ApprovalRoster.from_file("approval-roster.json", clock=clock)
authorized_request = SignedApprovalBridge(roster, coordinator_backend).approve(
    signed_decision
)
```

Here `coordinator_backend` is the trusted host's already configured
`CoreBackend`; the fully self-contained construction is in the runnable example.

It loads the pending request, verifies the signed event with the public-key
roster, then forwards the verified actor, assurance, exact evidence ID and a
non-secret signature digest to internal approval ingestion. Those provenance
fields are signed into authorization and retained in the durable request. The
bridge is deliberately absent from agent MCP.

For authorization tokens between coordinator and broker, `Ed25519AuthorizationAuthority` retains the private key and `Ed25519AuthorizationVerifier` gives brokers verification-only public-key authority.
