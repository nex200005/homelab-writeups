# Internal Network Security Assessment — Home Lab Environment

**Date:** 23 November 2026 · **Author:** Matthew Renfroe

## Executive summary

The environment moved from a **moderate** to a **low** internal risk posture in a single assessment cycle: 6 of 10 findings were fully remediated and verified the same day, 2 were remediated with documented residuals, 1 was formally risk-accepted, and 1 is closed by a scheduled decommission.

The assessment found no internet exposure and confirmed that network segmentation between the attack-lab, monitored-workstation and home networks held in every direction tested. The material risks were all reachable from the internal home LAN:

- **Password-based SSH on 6 hosts**, including the router that enforces attack-lab containment.
- **An SNMP agent on the server's baseboard management controller (BMC) answering the default `public` community**, disclosing 1,506 configuration and inventory values without authentication.
- **SMB message signing not enforced** on the primary file server, plus legacy NetBIOS services.
- **Cleartext (HTTP-only) administration and outdated firmware** on the core managed switch.

| Metric | Before | After |
| --- | --- | --- |
| Hosts accepting SSH password authentication | 6 | 0 |
| Open TCP services on owned infrastructure | 26 | 19 |
| Unauthenticated SNMP values readable | 1,506 | 0 |
| File servers enforcing SMB signing | 0 of 1 | 1 of 1 |
| Medium findings without a remediation | 5 | 0 |

The principal residual risk is architectural: management interfaces share a flat network with a household workstation. The owner accepted this risk, and the hardening above limits what that position can reach to authenticated web consoles. Section 8 describes a source-restriction control that would close it without moving any user.

## Scope and rules of engagement

The assessment covered all infrastructure on the home LAN (`192.168.0.0/24`) plus the boundaries of two lab VLANs, and was performed by the environment owner with full authorization on 23 November 2026.

**Network zones**

| Zone | Subnet | Purpose |
| --- | --- | --- |
| Home LAN | 192.168.0.0/24 | Infrastructure, management interfaces, one household workstation |
| Monitored VLAN 20 | 192.168.20.0/24 | Owner's workstation, behind a virtual lab router |
| Attack-lab VLAN 30 | 192.168.30.0/24 | Isolated attacker and vulnerable-target VMs, no internet by default |

**In scope (16 hosts)**

| Host | Role |
| --- | --- |
| .1 / .2 | Edge gateway (UniFi Cloud Gateway Ultra), incl. secondary address |
| .3 | Managed switch (TP-Link TL-SG108E) |
| .6 | Virtual lab router (Debian, nftables): VLAN 20/30 boundary |
| .47 / .49 / .51 | Proxmox VE hypervisors |
| .48 | Dell iDRAC8 BMC |
| .50 | File server (Samba in an LXC container) |
| .52 | Proxmox Datacenter Manager |
| .128 | DNS filter (Pi-hole) |
| .222 | Legacy file server, pending decommission |

**Out of scope:** four commercial network-monitoring appliances (.38, .55, .58, .142). Their open services were recorded for completeness but not tested, and vendor configuration is not discussed in this report.

**Rules of engagement:** discovery, port and service enumeration, and read-only NSE scripts only. No exploitation, credential guessing or denial-of-service testing was performed. Every fix was rescanned to confirm it.

## Methodology

Testing followed a discover, assess, remediate and verify cycle from four vantage points, so that every finding was judged by who can actually reach it.

1. **Discovery:** host discovery across the LAN, with each live address attributed by MAC address and the gateway's client list.
2. **Assessment:** full TCP port scan (all 65,535 ports) with service detection, a top-100 UDP scan, then targeted read-only checks of SSH authentication methods, SMB dialects and signing, TLS protocols and ciphers, IPMI and SNMP.
3. **Remediation:** fixes applied in priority order, with configuration syntax checked before reload and a console fallback held for every host.
4. **Verification:** each fix was rescanned immediately, then a final full rescan was run from the original vantage point.

| Vantage point | Represents |
| --- | --- |
| Owner workstation (VLAN 20) | A compromised workstation routed into the LAN |
| Hypervisor on the LAN | Any device on the flat home LAN, incl. the household PC |
| Attack-lab VM (VLAN 30) | An attacker inside the lab |
| Internet, via edge gateway policy review | An external attacker |

**Tooling:** Nmap 7.80 and 7.993 (Windows), Nmap 7.95 (Debian), Net-SNMP `snmpwalk`, `ipmitool`, `curl`. The baseline scan used Nmap 7.80 and the final scan 7.993. Port and service results compare directly; script results were re-run on current versions after 7.80 produced two known false negatives (TLS 1.3 detection, SSH authentication methods against OpenSSH 10).

**Severity ratings** use a qualitative scale based on exploitability from the reachable vantage point and the impact on confidentiality, integrity or availability:

| Rating | Meaning |
| --- | --- |
| High | Direct compromise of a host or control with little effort |
| Medium | Credible path to compromise or significant disclosure; needs a foothold or additional step |
| Low | Limited disclosure or defense-in-depth gap |
| Info | No direct risk; noted for context or as a positive control |

## Summary of findings

Ten findings were raised: five Medium, two Low-Medium, two Low and one Low (structural). No High or Critical issues were identified.

| ID | Finding | Affected | Severity | Status |
| --- | --- | --- | --- | --- |
| H-01 | SSH password authentication enabled | 6 hosts incl. lab router | Medium | Remediated |
| H-02 | Lab router SSH reachable from VLAN 20 and LAN | .6 | Medium | Remediated |
| H-03 | BMC SNMP agent answers default `public` community | .48 | Medium | Remediated |
| H-04 | SMB signing not required; NetBIOS enabled | .50 | Medium | Remediated |
| H-05 | Switch: cleartext HTTP admin, 2020/2021 firmware | .3 | Medium | Partially remediated (firmware) |
| H-06 | BMC: TLS 1.1 and weak ciphers accepted | .48 | Low-Medium | Remediated, 1 residual cipher |
| H-07 | BMC: legacy SSH (OpenSSH 7.4), 6-hour clock drift | .48 | Low-Medium | Remediated |
| H-08 | rpcbind exposed on TCP/UDP 111 | .47, .49, .51 | Low | Remediated |
| H-09 | Flat management network shared with household workstation | LAN | Low (structural) | Risk accepted |
| H-10 | Legacy file server with prior SMB configuration | .222 | Low | Open, decommission planned |

## Detailed findings

Each finding below lists its evidence, impact, the remediation applied and how it was verified.

### H-01 — SSH password authentication enabled (Medium)

**Affected:** lab router (.6), hypervisors (.47, .49, .51), file server (.50), Datacenter Manager (.52).

**Evidence:** `nmap --script ssh-auth-methods` reported `publickey` and `password` on all six hosts.

**Impact:** any device on the LAN could run unlimited online password guessing against root on every hypervisor and on the router that enforces lab containment. One weak or reused password would give full control of the virtualization layer.

**Remediation:** Ed25519 key pairs were deployed, protected by a passphrase and held in ssh-agent. Key-only login was confirmed on each host before passwords were disabled with a drop-in configuration (`PermitRootLogin prohibit-password`, `PasswordAuthentication no`, `KbdInteractiveAuthentication no`), with `sshd -t` checking syntax before reload. SSH was disabled entirely on the router and the file server, which are managed through the hypervisor console.

**Verification:** a rescan showed `publickey` only on .47, .49, .51 and .52; port 22 `filtered` on .6 and `closed` on .50.

### H-02 — Lab router SSH reachable from VLAN 20 and LAN (Medium)

**Evidence:** OpenSSH 10.0 was listening on the router's LAN address. The router's nftables input chain explicitly accepted TCP 22 from `192.168.0.0/24` and `192.168.20.0/24`, contradicting the documented intent that SSH be disabled.

**Impact:** the router is the only control separating the attack lab from production networks. Remote access to it, combined with H-01, created a path to disable containment.

**Remediation:** the SSH service was disabled and both accept rules were removed, with the ruleset validated by `nft -c` before reload.

**Verification:** port 22 `filtered`; the router exposes **zero** open TCP ports in the final scan.

### H-03 — BMC SNMP agent answers the default community (Medium)

**Evidence:** `snmpwalk -v2c -c public` against the iDRAC returned the system MIB and **1,506 values** from the vendor tree, including BMC firmware version (2.86.86.86), server model, service tag \[redacted\], express service code, management URL and component health.

**Impact:** unauthenticated reconnaissance. An attacker learns the exact hardware and firmware build to target known BMC vulnerabilities, and the asset's support identity. The agent is read-only, so no configuration change was possible through it.

**Remediation:** the SNMP agent was disabled on the iDRAC.

**Verification:** `snmpwalk` with SNMPv1 and v2c returns `Timeout: No Response`.

### H-04 — SMB signing not required; NetBIOS enabled (Medium)

**Evidence:** `smb2-security-mode` reported *message signing enabled but not required*. Dialects 2.02 to 3.11 were accepted, and NetBIOS was listening on TCP 139 and UDP 137.

**Impact:** unsigned SMB sessions can be relayed or tampered with by an on-path attacker (NTLM relay). This becomes a primary lateral-movement technique once an Active Directory lab is introduced.

**Remediation:** `server signing = mandatory`, `server min protocol = SMB3`, `disable netbios = yes` and `smb ports = 445` were set, and the `nmbd` service was disabled.

**Verification:** only dialect 3.1.1, with *signing enabled and required*; TCP 139 and UDP 137 `closed`. Client access was confirmed working.

### H-05 — Switch: cleartext administration and outdated firmware (Medium)

**Evidence:** the management interface is served over HTTP only. The firmware was build 20211209; during remediation it was briefly installed at 20201208 from a regional download page.

**Impact:** administrator credentials cross the network in cleartext, and embedded web servers on legacy firmware are a common source of authentication-bypass flaws.

**Remediation:** the configuration was backed up, firmware updated to build 20250710 (verified against the hardware revision before flashing), and the administrator password replaced with a unique credential. VLAN and PVID configuration was confirmed intact afterwards.

**Residual:** this hardware cannot serve HTTPS. Exposure is limited by the unique credential and the source restrictions recommended in section 8.

### H-06 — BMC accepts TLS 1.1 and weak ciphers (Low-Medium)

**Evidence:** `ssl-enum-ciphers` showed TLS 1.1 and 1.2 with 15 suites, including CBC/SHA-1, SEED, Camellia and non-forward-secret DHE options, and the client chose the cipher.

**Remediation:** set *TLS 1.2 Only*, applied a custom cipher string restricted to ECDHE/DHE AES-GCM, and reset the BMC so the web server would load it.

**Verification:** TLS 1.2 only, with 3 ECDHE AES-256 suites. **Residual:** `TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA` remains and the client still chooses the cipher, a firmware limitation of iDRAC8. All suites rate A.

### H-07 — BMC legacy SSH and clock drift (Low-Medium)

**Evidence:** OpenSSH 7.4 (2016), which cannot be updated on this firmware. HTTP `Date` headers were 6 hours ahead of UTC (local time labeled as GMT).

**Impact:** an unpatchable remote service, and inaccurate timestamps that break event correlation during an investigation.

**Remediation:** BMC SSH disabled; NTP and the correct time zone configured. IPMI over LAN was tested and found already disabled (no response to *Get Channel Authentication Capabilities*).

**Verification:** port 22 `closed`; BMC clock within 1 second of a reference host.

### H-08 — rpcbind exposed on hypervisors (Low)

**Evidence:** rpcbind open on TCP and UDP 111 on all three hypervisors, with no NFS storage in use.

**Impact:** discloses registered RPC services and can be abused for UDP reflection and amplification.

**Remediation:** `rpcbind.service` and `rpcbind.socket` disabled and masked.

**Verification:** TCP and UDP 111 `closed` on all three hosts.

### H-09 — Flat management network (Low, structural)

**Evidence:** every management interface shares `192.168.0.0/24` with a household workstation. Gateway policy shows *Internal → Gateway: Allow All*.

**Impact:** a compromise of that workstation reaches every administrative web console directly.

**Decision:** a dedicated network and zone for the workstation were designed and staged, but the owner **accepted the risk** to avoid disrupting the user. H-01 to H-08 now limit this position to authenticated HTTPS consoles.

### H-10 — Legacy file server (Low)

**Evidence:** the former file server (.222) still offers SMB on 139/445 with signing not required. Its data has been migrated to .50.

**Remediation plan:** power off after the post-migration hold period, then delete.

## Positive observations

Several controls were tested and held, which is why no finding exceeded Medium.

- **No internet exposure.** The edge gateway has zero port forwards and UPnP is disabled. Internet-to-LAN and internet-to-gateway policies end in *Block All*; the only inbound allowances are return traffic and IPv6 control messages.
- **Segmentation verified in all directions.** From the LAN, a sweep of all 512 addresses in VLANs 20 and 30 reached only the lab router's own interface; workstation and lab hosts were `filtered` on every port tested. Earlier tests confirmed the attack lab cannot reach the LAN, the workstation VLAN or the internet.
- **Deception control active.** The gateway's honeypot (.2) emulates FTP, SSH, Telnet, SMTP, POP3, SMB, MSSQL and HTTP services and was triggered by the assessment's own discovery scan.
- **Strong cryptography on core platforms.** Proxmox web interfaces offer TLS 1.2 (AEAD) and TLS 1.3 only, with server-chosen ciphers. All OpenSSH servers support post-quantum hybrid key exchange (`mlkem768x25519-sha256`) and strict key exchange, which mitigates Terrapin.
- **IPMI over LAN disabled** on the BMC, removing the RAKP hash-disclosure and cipher-zero attack surface.
- **DNS filtering is tightly bound.** Pi-hole answers only on its LAN interface and exposes no services beyond DNS and its HTTPS console.

## Remediation verification

The final full TCP scan from the original vantage point (owner workstation, VLAN 20) confirmed every remediation, reducing open services on owned infrastructure from 26 to 19.

| Host | Baseline open TCP | Final open TCP | Change |
| --- | --- | --- | --- |
| .6 Lab router | 22 | none | SSH removed; host absent from `--open` results |
| .47 Hypervisor | 22, 111, 3128, 8006 | 22, 3128, 8006 | rpcbind removed; SSH key-only |
| .49 Hypervisor | 22, 111, 3128, 8006 | 22, 3128, 8006 | rpcbind removed; SSH key-only |
| .51 Hypervisor | 22, 111, 3128, 8006 | 22, 3128, 8006 | rpcbind removed; SSH key-only |
| .48 BMC | 22, 80, 443, 5900 | 80, 443, 5900 | SSH removed; SNMP off; TLS 1.2 only |
| .50 File server | 22, 139, 445 | 445 | SSH and NetBIOS removed; SMB 3.1.1 with signing |
| .52 Datacenter Manager | 22, 8443 | 22, 8443 | SSH key-only |
| .3 Switch | 80 | 80 | Firmware 20250710; unique credential |
| .128 DNS filter | 53, 80, 443 | 53, 80, 443 | No change required |

UDP and configuration changes not visible in a TCP scan were verified separately: UDP 111 and 137 `closed`, SNMP `Timeout: No Response`, SMB signing *required*, BMC clock within 1 second of reference.

The gateway (.1), honeypot (.2), out-of-scope appliances and legacy file server (.222) were unchanged. The gateway's one ephemeral high port changed number between scans, which is expected behavior.

## Residual risk and recommendations

Residual risk is **Low**. It consists of authenticated web consoles reachable from the flat LAN (H-09), cleartext switch administration (H-05), one legacy BMC cipher (H-06) and the pending decommission (H-10).

| Priority | Recommendation | Addresses | Effort |
| --- | --- | --- | --- |
| 1 | Decommission the legacy file server after the migration hold period | H-10 | Low |
| 2 | Restrict management interfaces by source address (Proxmox firewall `management` IPSet, iDRAC IP Range, gateway policy for the switch and gateway consoles) to the workstation VLAN and required hosts | H-05, H-09 | Medium |
| 3 | Enable TOTP two-factor authentication for `root@pam` on all hypervisors and for the gateway and Datacenter Manager accounts | H-09 | Low |
| 4 | Re-run this assessment quarterly and after any new service is deployed, from the same vantage points, and diff against this baseline | All | Low |
| 5 | Before the planned Active Directory lab goes live, enforce SMB signing and LDAP signing and channel binding on all domain members | H-04 (forward) | Medium |

Recommendation 2 is the preferred closure for H-09: it delivers the effect of a management VLAN with no IP changes and no disruption to household users. It should be staged one device at a time, with a console session held open, to avoid lockout.

## Appendix: commands used

The commands below reproduce the assessment and its verification. All are read-only except the remediation steps already described in section 5.

**Discovery and enumeration**

```bash
nmap -sn 192.168.0.0/24 -oN 01-lan-hosts.txt
nmap -sV -p- -T4 --open -oN 02-infra-tcp.txt 192.168.0.xxx
nmap -sU --top-ports 100 -T4 --open -oN 04-infra-udp.txt 192.168.0.xxx
```

**Targeted checks**

```bash
nmap -p22 --script ssh-auth-methods --script-args ssh.user=root 192.168.0.xxx
nmap -p139,445 --script smb-protocols,smb2-security-mode 192.168.0.xxx
nmap -p443 --script ssl-enum-ciphers 192.168.0.48
nmap -p8006 --script "+ssl-enum-ciphers" 192.168.0.xxx
nmap -sU -p623 --script ipmi-version,ipmi-cipher-zero 192.168.0.xxx
ipmitool -v -I lanplus -H 192.168.0.48 -U root -P <invalid> chassis status
snmpwalk -v2c -c public 192.168.0.xxx 1.3.6.1.2.1.1
snmpwalk -v2c -c public 192.168.0.xxx 1.3.6.1.4.1.674.10892.5 | wc -l
curl -skI https://192.168.0.xxx | grep -i '^date'; date -u
```

**Segmentation (from the LAN)**

```bash
nmap -sn 192.168.20.0/24 192.168.30.0/24
nmap -Pn -p22,80,443,445,3389 192.168.20.xxx 192.168.30.xxx 192.168.30.xxx
```

**Tool notes:** `ssl-enum-ciphers` does not run on Proxmox port 8006 without the `+` prefix, because the port also answers plain HTTP. Nmap 7.80 could not enumerate SSH authentication methods against OpenSSH 10 or detect TLS 1.3. Debian's `snmp` package ships without MIBs, so numeric OIDs were used.
