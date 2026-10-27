# Security and privacy

WiFi Scout interprets untrusted wireless advertisements and optional local captures. Its outputs are observations and comparisons, not network authentication or proof that a network is free of attackers.

## Intended boundary

The dashboard is a local, single-user utility bound to `127.0.0.1`. It must not be exposed through public hosting, a reverse proxy, or a port forward. Do not run it as root. Local processes running under your account may access the same observations and files; the dashboard does not establish an isolation boundary against a compromised local account.

SSID text is hostile input. It must remain text in the browser, have control characters escaped at the terminal, and never be interpolated into a shell command. Scan-triggering and history-changing requests require the local request token. Imported files and baseline JSON must be handled as untrusted data.

The app does not perform injection, password attacks, traffic manipulation, automatic connections, or client probing. Normal NetworkManager discovery can transmit OS probe requests. Advanced capture requires an existing monitor interface and appropriate system capture permissions; the app does not reconfigure interfaces or stop network services.

No history is written by default. Explicit baselines contain access-point names, BSSIDs, advertised configuration, and observation times, which may disclose visited places. Default capture processing does not retain application payloads or nearby client identifiers. User-provided capture files may already contain those fields; users remain responsible for their source files, exported output, and backups.

## Reporting a vulnerability

Avoid posting private scan data, captures, credentials, or an exploit against a real network in a public issue. If the published GitHub repository has private vulnerability reporting enabled, use its **Security → Report a vulnerability** flow. Otherwise, ask the repository maintainers for a private reporting channel without including sensitive details. This source checkout does not claim that any particular hosted reporting channel has been configured.

Please include the affected version, a minimal synthetic reproduction, the expected boundary, and the observed result. Useful reports include command/terminal injection, HTML execution, remote access to the local service, unintended persistence of client/payload data, and recommendations that bypass explicit network eligibility.

This project is an initial MVP. It has no promised response SLA or independently audited security certification. Only the current development version is maintained until a release-support policy is established.
