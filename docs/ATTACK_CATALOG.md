# Attack technique catalog

Curricular inspiration: **CU Boulder MSCS _Attacking the Network_** and **_Security & Ethical Hacking: Attacking Unix and Windows_** course topic outlines supplied by the project owner (2026-10-09). These are research themes and defensive lab checks, not a reproduction of coursework, and not executable exploitation procedures.

| ID | Curriculum topic | Security hypothesis / authorized evidence | Reference |
|---|---|---|---|
| NET-01 | Network layers, packets, Ncat | Check whether actual approved connectivity agrees with network graph declarations | [Kubernetes networking](https://kubernetes.io/docs/concepts/services-networking/) |
| NET-02 | Networked shells, Netcat | Detect inadvertent exposure of management/debug listeners from approved inventory | [Ncat](https://nmap.org/book/ncat-man.html) |
| NET-03 | Scapy, interface programming, inspecting traffic | Analyze saved synthetic PCAPs and compare protocol observations with topology | [Scapy](https://scapy.readthedocs.io/en/latest/) |
| NET-04 | Nmap, host discovery, recon, advanced scan ethics | Compare known lab host/port inventory with bounded, low-rate observations | [Nmap](https://nmap.org/book/man.html) |
| NET-05 | MITM, code execution primer, HTTPS, SSLStrip and defenses | Audit ingress TLS, HSTS, redirect behavior and transport trust, without interception outside an isolated lab | [OWASP TLS](https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html) |
| NET-06 | SSH local, remote, dynamic forwarding, SOCKS/Proxychains | Model how approved forwarding configuration can change trust boundaries; avoid unapproved tunnels | [OpenSSH](https://man.openbsd.org/ssh) |
| HOST-01 | Unix filesystem, processes, security basics | Review ownership, permissions, mounted paths, user IDs and runtime context | [Kubernetes Pod Security](https://kubernetes.io/docs/concepts/security/pod-security-standards/) |
| HOST-02 | SETUID and Unix privilege escalation | Inspect approved container images for unexpectedly elevated execution paths | [CWE](https://cwe.mitre.org/) |
| HOST-03 | Shared-library hijacking, LD_PRELOAD/LD_LIBRARY_PATH, editors | Audit writable library paths and unsafe elevated loader configuration in synthetic images | [CWE](https://cwe.mitre.org/) |
| HOST-04 | SSH session hijacking, agent forwarding, ControlMaster, lateral movement | Analyze credential/agent forwarding risk using synthetic identities and owned configurations | [ATT&CK Lateral Movement](https://attack.mitre.org/tactics/TA0008/) |
| HOST-05 | SSH keyphrase cracking | Audit credential policies with fake test keys, not production secrets | [OWASP secrets](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html) |
| HOST-06 | x86, CALL/RET, memory corruption, debugger, remote code execution, shellcode | Map versions to advisories and test owned intentionally vulnerable binaries with bounded non-destructive checks | [CVE](https://www.cve.org/), [CWE](https://cwe.mitre.org/) |
| K8S-01 | Extension: NetworkPolicy | Missing/default-allow segmentation can permit unexpected paths to a synthetic canary | [NetworkPolicy](https://kubernetes.io/docs/concepts/services-networking/network-policies/) |
| K8S-02 | Extension: Kubernetes RBAC/service accounts | Excessive identity permissions create paths to unintended operations | [RBAC practices](https://kubernetes.io/docs/concepts/security/rbac-good-practices/) |
| K8S-03 | Extension: Kubernetes workload security | Ingress, pod security contexts, image provenance and token mounts affect path feasibility | [Security checklist](https://kubernetes.io/docs/concepts/security/security-checklist/) |
| CLOUD-01 | Extension: AWS/Akash IAM, network controls, logging | Provider identities and firewall/load-balancer controls create edges beyond the cluster | [ATT&CK cloud](https://attack.mitre.org/matrices/enterprise/cloud/) |

## Priorities
**First:** K8S-01, K8S-02, NET-01, NET-04, K8S-03.
**Next:** CLOUD-01, NET-03, NET-05, HOST-01/02.
**Later, in dedicated isolation:** traffic manipulation, forwarding, credential security and executable exploitation labs.

## Test-card format
For each technique create a case recording: hypothesis; primary citations/technique identifiers; approved scope; preconditions; assumed graph edges; safe validation; request budget; expected/observed evidence; timestamps/provenance; false positives; remediation; legitimate workflow regression test.

For version/CVE findings, confirm relevant build, configuration, patches and applicability. A scanner hit alone is not proof of exploitability.
