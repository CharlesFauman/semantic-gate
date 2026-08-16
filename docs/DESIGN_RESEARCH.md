# Design research

Semantic Gate borrows established security patterns rather than inventing an agent-only permission model.

## Systems reviewed

- [Model Context Protocol authorization](https://modelcontextprotocol.io/specification/2025-06-18/basic/authorization) and [security best practices](https://modelcontextprotocol.io/docs/2025-11-25/tutorials/security/security_best_practices): bind tokens to their audience, do not pass upstream tokens through, and defend against confused-deputy and session-hijacking attacks.
- [Open Policy Agent](https://www.openpolicyagent.org/docs): keep policy decisions separate from enforcement points and express decisions as policy-as-code.
- [Cedar](https://docs.cedarpolicy.com): model authorization requests explicitly as principal, action, resource and context; validate policies against a schema.
- [OpenFGA](https://openfga.dev/docs/concepts) and [SpiceDB](https://authzed.com/docs/spicedb/concepts/schema): model principals, resources and relationships independently of application prompts. Both ecosystems now discuss agent and MCP authorization use cases.
- [LangGraph interrupts](https://docs.langchain.com/oss/python/langgraph/interrupts) and [Pydantic AI deferred tools](https://pydantic.dev/docs/ai/tools-toolsets/deferred-tools): persist deferred work and resume from explicit external decisions rather than relying on model conversation memory.
- [HashiCorp Vault secrets engines](https://developer.hashicorp.com/vault/docs/secrets): keep credentials in a broker, prefer short-lived or dynamically issued credentials, and do not expose root credentials to workloads.
- [SPIFFE](https://spiffe.io/docs/latest/spiffe-about/overview/): give workloads verifiable identities and bind authorization to the workload, trust domain and audience.
- [Apple Automation privacy controls](https://support.apple.com/guide/mac-help/allow-apps-to-automate-and-control-other-apps-mchl108e1718/mac): local GUI automation is privileged and should be granted narrowly by the operating system.
- [Microsoft Just Enough Administration](https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/jea/overview?view=powershell-7.6): expose constrained commands and virtual identities instead of broad administrative shells, with transcripts and logs.
- [NIST SP 800-207 Zero Trust Architecture](https://csrc.nist.gov/pubs/sp/800/207/final): do not grant implicit trust based only on network location; authenticate and authorize each access to a resource.

## Adopted patterns

1. The coordinator is a policy decision point; node brokers and plugins are enforcement points.
2. An action request has a host-authenticated principal, semantic action, closed parameters, trusted host context and immutable request hash.
3. Agents may propose, inspect and restrictively cancel. Human approval and execution are separate authorities.
4. Policy decides required control. A caller may request stricter review but
   cannot lower, bypass or replace the policy-selected requirement.
5. Credentials stay behind plugins. An agent sees a semantic action, not a vendor token.
6. Local and remote execution use the same request and approval graph.
7. Distributed execution uses a single-use, expiring lease bound to request, policy, node, plugin, action and parameter hash.
8. Node plugins expose reviewed semantic recipes. They do not expose generic shell, AppleScript text, PowerShell text, GUI coordinates or arbitrary keystrokes.
9. Version-2 authorized requests and request idempotency survive coordinator restart. Broker `executing` records remain reserved until explicit operator-confirmed recovery to `unknown`; unresolved pending approvals require explicit cancellation and reproposal.
10. A deployment must distinguish catalogued, shadowed and enforced actions. A gate is not an enforcement boundary while the agent retains direct credentials, shell access or raw downstream tools.

## Deliberate differences

Semantic Gate is not a replacement for OPA, Cedar, OpenFGA, SpiceDB, Vault, SPIFFE or an operating-system sandbox. A deployment may use those systems behind the generic interfaces. The project focuses on deterministic multi-step action workflows, exact human-evidence binding and adapter-independent local/remote execution.
