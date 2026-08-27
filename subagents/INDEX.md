# Specialist roster

Orchestrator: NEVER read this file or any file here — the roster is already in your persona.
Spawned children read ONLY their own `<id>.md`.

- `stavros-ad` — Enumerate and test Active Directory: netexec/impacket/responder/bloodhound/enum4linux-ng. → read `subagents/stavros-ad.md`
- `stavros-authed` — Re-test endpoints behind login with auth.json identities: IDOR/BOLA, priv-esc, authed injection. → read `subagents/stavros-authed.md`
- `stavros-authn` — Test authentication/session: login enumeration, password-reset/OTP/MFA flaws, JWT, OAuth/OIDC, cookies. → read `subagents/stavros-authn.md`
- `stavros-authz` — Test broken access control: IDOR/BOLA, missing auth, privilege escalation via object/ID swap. → read `subagents/stavros-authz.md`
- `stavros-breach` — Exploit a candidate network service in scope (via msf.js) to get the initial session. → read `subagents/stavros-breach.md`
- `stavros-cleanup` — Remove every tracked artifact/session; verify the teardown ledger is empty. → read `subagents/stavros-cleanup.md`
- `stavros-cloud` — Cloud surface: metadata via SSRF, exposed S3/GCS/Azure buckets, provider fingerprint. → read `subagents/stavros-cloud.md`
- `stavros-csrf` — Find CSRF on state-changing endpoints: missing/stale tokens + SameSite=None/absent cookies. → read `subagents/stavros-csrf.md`
- `stavros-injection` — Test command/template/header injection, open redirect, SSTI/deser/NoSQLi/LFI/proto-pollution. → read `subagents/stavros-injection.md`
- `stavros-lateral` — Move laterally between in-scope hosts. Confirm-tier: every move needs explicit user sign-off. → read `subagents/stavros-lateral.md`
- `stavros-mapper` — Map endpoints, parameters, forms, auth flows and roles; record per-class candidates via map.js. → read `subagents/stavros-mapper.md`
- `stavros-network` — Scan in-scope networks/hosts: ports, services, versions, and OS fingerprint. → read `subagents/stavros-network.md`
- `stavros-osint` — Passive OSINT on a domain/organization: emails, hosts, ASNs, exposed services, metadata. → read `subagents/stavros-osint.md`
- `stavros-persist` — Install minimal persistence / exfiltrate, only on explicit per-action confirmation. → read `subagents/stavros-persist.md`
- `stavros-postex` — On a controlled session, run local enumeration, privesc recon, and read-only looting. Auto-tier only. → read `subagents/stavros-postex.md`
- `stavros-recon` — Map the attack surface of a host: subdomains, live hosts, tech stack, historical URLs. → read `subagents/stavros-recon.md`
- `stavros-reporter` — Consolidate findings, state, and chains into a single severity-ordered report. → read `subagents/stavros-reporter.md`
- `stavros-sqli` — Test candidate parameters for SQL injection (error/boolean/time-blind) and prove it safely. → read `subagents/stavros-sqli.md`
- `stavros-ssrf` — Find SSRF on URL-fetching params (blind via oob.js, reflected via response/follow). → read `subagents/stavros-ssrf.md`
- `stavros-vet` — Analyze a repo the operator provides: what it does, build/maintenance quality, better alternatives, and wheth… → read `subagents/stavros-vet.md`
- `stavros-wireless` — Assess an in-scope WiFi network: passive recon, handshake/PMKID capture, WPA/WPS cracking. → read `subagents/stavros-wireless.md`
- `stavros-xss` — Find reflected/stored/DOM XSS and confirm real execution context (not just reflection). → read `subagents/stavros-xss.md`
