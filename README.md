# My Interns

This is a collection of agents that I am using to
make my job easier. The idea is that every network
pentest is just a HITL agent-swarm that I can sign
off on.

## Structure

Multiple Agents in this directory right now. Later there will be
an orchestration layer that will deal with everyone and ensure the
workflow is consistent.

### Agents

There is currently a *very basic* web pentester agent and a network
recon agent. On the docket are:

* File and Credential Discovery
* DNS Enumeration (Subdomains, MX, TXT)
* Rote Auditing (SSL/TLS Auditing, SSH Cipher Best Practices, SMB)
* Vulnerability Scanning (wpscan, nuclei) & CVE Research
* Active Directory Chains (bloodhound, bloodyAD)
  `- this may be split into multiple agents
* Reporting Agent (structured output from all agents -> pandoc)

### Findings

All agents emit findings against one standardized contract: [`findings.py`](findings.py)
(the schema + `emit_finding` helper) keyed into the company findings dictionary
[`findings_catalog.json`](findings_catalog.json). Two emission patterns, picked by agent
type: **deterministic** agents call `findings.emit_finding(...)` directly; **LLM-driven**
agents (e.g. the web pentester) wrap it in an in-process MCP tool the model calls mid-run.
See the `findings.py` module docstring for details.

## Usage

You can invoke the swarm at the orchestration level
or call individual agents.

### Recon Agent

This agent is mostly a deterministic, phased `nmap` pipeline (host discovery → port
scan on live hosts → targeted service/script scan) with an LLM fallback that only kicks
in to troubleshoot a phase that errors, times out, or returns nothing. It consumes a
scope of IPs, CIDRs, URLs, and/or hostnames (e.g. the OSINT agent's output — hostnames
are resolved to IPs; it does **not** enumerate subdomains itself).

Every run writes a durable, self-describing artifact other agents can consume:

```
network-recon-agent/artifacts/recon/<run_id>/
    report.json          # canonical, typed ScanReport (the schema contract)
    phase-*.xml          # raw nmap XML evidence
    targets-*.txt        # exact inputs
network-recon-agent/artifacts/recon/latest.json   # pointer to the newest report
```

The methodology lives in [`phases.py`](network-recon-agent/phases.py) — edit
`DEFAULT_PHASES` to change it. The output schema is in
[`schema.py`](network-recon-agent/schema.py); downstream agents ingest a report with
`load_report(path)`.

**Privileges:** the `-sS`/`-sU` phases need raw sockets. Grant the binary the capability
once (preferred over per-run `sudo`):

```bash
sudo setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip "$(command -v nmap)"
```

Without it, TCP degrades to `-sT` and UDP phases are flagged blocked (never silently empty).

```bash
# CLI
./.venv/bin/python ./network-recon-agent/agent.py \
  --scope 10.0.0.0/24 --scope example.com \
  --exclude-file exclude.txt --out report.json

# Embedded
#   from agent import run_recon, load_report
#   report = await run_recon(["10.0.0.0/24"])
```

### Web Pentest Agent

```bash
./.venv/bin/python ./web-pentester/agent.py \
--target https://url.xyz \
--objective "Do Something with this web application"
```
