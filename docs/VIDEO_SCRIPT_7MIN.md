# SecureMailScope — 7-minute video script

**Problem statement:** SIH26159 — AI-Assisted Cryptographic Security Posture Assessment for Secure Email Communications (NTRO)
**Main capture:** `~/Downloads/CAP-0027-F-0001.pcapng` (shows in the app as **CAP-0016**)
**PQC capture:** `15-pqc-readiness.pcap` (already loaded as **CAP-0010**)
**Length:** 7:00 · about 1,000 words of narration

**Bold quotes** are spoken. *Italics* are what to do on screen. `[CLICK]` is an action.

---

## Before recording (checklist)

1. `cd sih26 && docker compose up -d` → wait 20 s → open **http://localhost:5173**.
2. Dark theme (sun/moon button, top right). Browser at 1440×900 or larger, zoom 100%, bookmarks bar hidden.
3. Keep **Finder → Downloads** open beside the browser, showing `CAP-0027-F-0001.pcapng`.
4. Check that **CAP-0010 · 15-pqc-readiness.pcap** appears in the Captures table.
5. Do one full dry run so every page is cached.
6. Start on the **Captures** page (sidebar → Captures).

> This file was uploaded once during setup. Uploading it again reopens the same assessment (CAP-0016) and re-runs the analysis. Evidence is identified by SHA-256, so it is never duplicated. That's a good line for Scene 2.

---

## Timeline

| Time | Scene | Screen |
|---|---|---|
| 0:00 – 0:40 | 1. The problem | Captures page |
| 0:40 – 1:10 | 2. What we built | Captures page |
| 1:10 – 1:50 | 3. Upload and pipeline | New analysis dialog |
| 1:50 – 2:40 | 4. Overview and infrastructure map | Overview |
| 2:40 – 3:10 | 4b. AI Analyst | AI Analyst tab → ask two questions |
| 3:10 – 3:40 | 5. Trace one finding | Overview → Priority findings → F-0001 |
| 3:40 – 5:40 | **6. Post-quantum readiness (main segment)** | Sessions → TLS handshake · Post-Quantum tab · ⌘K → CAP-0010 · Simulate hybrid PQC |
| 5:40 – 6:25 | 7. Fix and verify | ⌘K → CAP-0016 → Remediation |
| 6:25 – 7:00 | 8. Report and close | Export → Assessment report (PDF) |

---

## Scene 1 — The problem (0:00 – 0:40)

*Screen: Captures page. Don't click anything yet.*

**"Email still carries an organisation's most sensitive information, and it's protected by TLS. But having TLS isn't the same as having *good* TLS. Real mail servers still negotiate old protocol versions, use weak ciphers, present expired certificates, or let STARTTLS be silently stripped so mail travels in cleartext."**

**"And there's a newer risk. An attacker can record encrypted email today and decrypt it years later with a quantum computer. That's called harvest-now, decrypt-later, and email is the ideal target because it stays sensitive for years."**

**"Wireshark shows you packets. It doesn't tell you how secure your email really is, what to fix first, or how ready you are for post-quantum cryptography. That's the gap we're closing."**

## Scene 2 — What we built (0:40 – 1:10)

*Screen: Captures page. Point at the Captures table, then press ⌘K once to show the command palette and close it.*

**"This is SecureMailScope, a passive forensic framework. It reads a packet capture and never touches a live server."**

**"It reconstructs every SMTP, IMAP and POP3 session, follows the STARTTLS upgrade, parses the TLS handshake, validates certificates, and checks everything against published standards like NIST SP 800-52 and the RFCs."**

**"On top of that sits our own machine learning, trained in-house with no external AI service. It classifies risk, spots anomalous TLS behaviour, and ranks what to fix first. Every conclusion is traced back to the exact packets that prove it."**

## Scene 3 — Upload and pipeline (1:10 – 1:50)

*`[CLICK]` **New analysis** (top right). Drag `CAP-0027-F-0001.pcapng` from Downloads onto **"Drop a capture file or click to browse"**.*
*Watch the four stages in the dialog turn green.*

**"I'll drop in a capture of real mail traffic. First the file is hashed with SHA-256. That's the chain-of-custody anchor, and every finding will carry it."**

*Point at stage 2, **"Validate capture and build evidence manifest"**: "CAP-0016 · 43 packets".*

**"The evidence manifest: 43 packets. If the same file is uploaded again, the hash matches and the existing case reopens instead of creating a duplicate."**

*Point at stages 3 and 4 as they complete.*

**"Next it indexes the TCP flows, reassembles the streams, rebuilds the email session, then runs the TLS, certificate, rule and model analysis. That takes a couple of seconds."**

*The dialog closes and the capture opens on its **Overview** tab. Point at the case header: file name, CAP-0016, 43 packets, SHA-256, and the tabs underneath.*

## Scene 4 — Overview and infrastructure map (1:50 – 2:40)

*Screen: Overview tab for CAP-0016.*

*Point along the metric strip: **Posture score 85 / 100 · Action required · 1 critical**.*

**"The posture score is 85, but it's flagged *Action required*. One critical finding outweighs any average. On the right, the posture breakdown shows each dimension. Hover the info icon and you see the standard it's measured against and how much evidence supported it. Behavioural consistency is *not assessed*, because one session isn't enough to build a baseline. We exclude it rather than guess."**

*Continue along the strip.*

**"One SMTP session, 100% encrypted, and STARTTLS adoption is 100%. Our model's risk index is 100, because the only session here is classified critical."**

**"Certificate coverage is 100%, because this session used TLS 1.2, where the certificate is visible. And notice PQC readiness: 25, Early. We'll come back to that."**

*Hover the **Infrastructure** map: client `127.0.0.1` → server `127.0.0.1:3303` → crypto nodes (TLS 1.2, the cipher suite) → weakness nodes on the right. Click the server node to open its detail drawer, then close it.*

**"The infrastructure map links every client, server, negotiated primitive and weakness. SMTP is running on port 3303, a non-standard port, and our protocol detector still found it by its greeting, not by the port number."**

## Scene 4b — AI Analyst (about 30 s; take the time from Scene 7)

*`[CLICK]` the **AI Analyst** tab. Point at the **Analyst brief**: each sentence has linked refs.*

**"This is our AI analyst. It runs entirely locally, and every sentence it writes is computed from the evidence, so each reference links to its proof."**

*In **Ask the analyst**, type: `Were any passwords exposed?` and press Enter. Then type `What if we renew the certificate?`.*

**"Our own intent model reads plain English, finds the right analysis and answers with citations. It can also run the remediation simulator before you change anything: renewing the certificate takes this capture from 85 to 96."**

*Point at **Attack paths** (stages with MITRE ATT&CK IDs) and the **Client TLS fingerprints** panel.*

**"Findings are correlated into attack scenarios mapped to MITRE ATT&CK, and client TLS stacks are clustered so unusual clients stand out."**

*(Tip: on the PQC capture, ask `Are we quantum safe?`. The answer includes the Mosca verdict.)*

## Scene 5 — Trace one finding (2:40 – 3:40)

*Scroll to **Priority findings** → `[CLICK]` **F-0001 · Certificate had already expired at capture time** (P1 82).*

**"This is the most important finding: priority P1. On the right is its chain of custody, from the evidence hash, to TCP stream 0, to the exact frame, the rule, the verdict, the fix, and the projected outcome. Every step links to its detail."**

*On the **Evidence** tab, scroll to **Session SMTP-0001** (the ladder diagram).*

**"Here's the reconstructed conversation, frame by frame. Server greeting at frame 4. The server advertises STARTTLS at frame 14. The client requests it at frame 17 and the server accepts at 18. The TLS handshake follows, then encrypted data. The ServerHello at frame 20 is outlined in red as evidence. That's where the certificate was presented."**

*`[CLICK]` the **Analysis** tab.*

**"The certificate expired on 20 August 2026. The traffic was captured on 24 September, so it had been expired for 35 days. We judge validity against the capture's own clock, not today's date. That's the right way to do forensics."**

*Scroll to **Session risk classification**.*

**"Our model classifies the session as critical, with 100% confidence. The explanation uses Shapley values: certificate validity alone adds three severity levels above this session's healthy baseline. It's not a black box."**

*(Optional, 5 seconds: point at **Copy Wireshark filter** and **Evidence slice** at the top right. "One click exports just these frames for Wireshark.")*

## Scene 6 — Post-quantum readiness, the main segment (3:40 – 5:40)

### 6a. The same session, seen through a quantum lens (3:40 – 4:20)

*`[CLICK]` the **Sessions** tab → row **SMTP-0001** → tab **TLS handshake**.*

**"Now the part we care about most: post-quantum readiness."**

*Point at the notice "The client offered TLS 1.3, but the server selected TLS 1.2", then at **Offered versions** and **Version**.*

**"Look at the handshake. The client offered TLS 1.3, but the server chose TLS 1.2. That matters, because hybrid post-quantum key exchange only exists in TLS 1.3. This server blocks the quantum-safe upgrade even though the client was ready for 1.3."**

*Point at **Offered by the client → Key exchange groups**: x25519, secp256r1, x448 … ffdhe8192.*

**"Every key-exchange group offered is classical: X25519, elliptic curves, finite-field Diffie-Hellman. No ML-KEM. So this session has forward secrecy today, but a future quantum computer can recover its key from a recording."**

### 6b. The PQC readiness score (4:20 – 4:50)

*`[CLICK]` the **Post-Quantum** tab.*

*Scroll to **Quantum risk forecast**: drag **Confidentiality period** from 10 to 15 years and watch the Mosca verdicts.*

**"Our quantum risk forecast applies Mosca's theorem: if the years this mail must stay secret, plus the years migration takes, exceed the years until a quantum computer exists, you must act now. With a 10-year confidentiality period, today's traffic is still sensitive when a 2030 or 2035 quantum computer arrives."**

**"The PQC readiness score is 25 out of 100: Early. The score-components table shows exactly why: five observable components, each with a stated weight: hybrid PQC negotiated, TLS 1.3 in use, clients offering PQC groups, ephemeral key exchange, traffic encrypted. This server passes only the last two."**

*Point at **Harvest-now, decrypt-later exposure**: 100.0% of sessions, all in "Classical ephemeral key exchange". Then scroll to **Migration plan**.*

**"And here's the exposure: 100% of sessions are in the harvest-now, decrypt-later tier. The migration plan is specific: first move this server to TLS 1.3, then enable hybrid ML-KEM."**

### 6c. When clients are ready but the server isn't (4:50 – 5:25)

*Press **⌘K**, type `pqc`, select **CAP-0010 · 15-pqc-readiness.pcap**, then `[CLICK]` the **Post-Quantum** tab.*

**"Here's a second capture from a more modern mail server. All seven sessions use TLS 1.3 and the classical posture score is 100, a perfect score."**

*Point at the readiness gauge (**45 · Early**, "Capped at 45…"), then at **Key-exchange groups**: X25519MLKEM768, offered 3 (42.9%), **Never selected**. Then at **Servers**: "Clients ready, server not".*

**"But PQC readiness is only 45. Three of the seven clients already offered the hybrid group X25519-MLKEM768, standardised in FIPS 203, and the server declined every time. The score is capped, because being ready isn't the same as being protected. A server can score 100 today and still be 100% exposed to harvest-now, decrypt-later. That's what our PQC module makes visible."**

### 6d. Simulate the post-quantum fix (5:25 – 5:40)

*`[CLICK]` **Simulate hybrid PQC** (top right). Remediation opens with **Enable hybrid post-quantum key exchange (X25519MLKEM768)** selected.*

*Point at the gauge (**PQC readiness 69 · Transitioning**, from 45), then the tiles **Hybrid PQC sessions 0 → 3** and **Harvest-now-decrypt-later exposed 100% → 57.1%**. Scroll to the **Post-quantum exposure** bars.*

**"The simulator applies the fix to a digital copy of the capture and re-runs every rule. Readiness goes from 45 to 69, now *Transitioning*. Three sessions move to hybrid ML-KEM, and exposure drops from 100% to 57%. The other four clients still need upgrading, and the simulator says so honestly."**

*`[CLICK]` **Configuration · Postfix** on the step, show the line `tls_eecdh_auto_curves = X25519MLKEM768 X25519 …`, then close.*

**"The exact Postfix change, with the OpenSSL 3.5 requirement noted."**

*(If time allows, 3 seconds: **Export → Cryptographic BOM (CycloneDX)**. "And the full inventory exports as a CycloneDX cryptographic bill of materials, the standard format for planning a PQC migration.")*

## Scene 7 — Fix and verify (5:40 – 6:25)

*Sidebar **Recent captures** → **CAP-0027-F-0001.pcapng** → **Remediation** tab. `[CLICK]` **Select all**.*

**"Back to our first capture. The planner orders the fixes by how much they improve the posture per unit of effort."**

*Point at step 1, **Re-issue the server certificate**, **85 → 96**. `[CLICK]` **Configuration · Unidentified SMTP server** and show the certbot command and verification commands. Close.*

**"Step one: re-issue the certificate. This server's banner doesn't name a known product, so we give generic guidance rather than guessing. For Postfix, Exim, Exchange or Dovecot, the exact config lines are generated. Each fix includes the openssl commands that prove it worked."**

*Scroll to the tiles and the **Infrastructure** map with **Compare** selected.*

**"The projected result: posture 85 to 96, zero failing findings, and the risk index from 100 down to 25. On the map, the resolved weakness is struck through."**

## Scene 8 — Report and close (6:25 – 7:00)

*`[CLICK]` **Export → Assessment report (PDF)**, then open the PDF. Scroll past the cover, contents and executive summary.*

**"Everything exports as JSON, HTML and PDF from one dataset, so they always agree. The PDF is a formal forensic report: document control, methodology, chain of custody, every finding with its frames and Wireshark filter, and a remediation plan."**

*Back to the **Overview** tab for the final shot.*

**"SecureMailScope: passive, evidence-backed, explainable, and focused on the next threat as well as today's. It tells you how secure your email is now, how ready it is for post-quantum cryptography, and exactly what to fix first. Thank you."**

---

## Numbers cheat-sheet

**CAP-0016 · CAP-0027-F-0001.pcapng**

| Item | Value |
|---|---|
| Packets / size | 43 packets · 8.4 KB |
| Sessions | 1 SMTP, `127.0.0.1:35634 → 127.0.0.1:3303` |
| STARTTLS frames | advertised #14 · requested #17 · accepted #18 · ClientHello #19 · ServerHello #20 |
| TLS | client offered 1.3 + 1.2 → server chose **TLS 1.2**, `TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384` |
| Groups offered | x25519, secp256r1, x448, secp521r1, secp384r1, ffdhe2048–8192 (no ML-KEM) |
| Certificate | `mail.testbed.local`, RSA 2048, SHA-256, expired 2026-08-20; captured 2026-09-24 → **35 days expired** |
| Chain | both signatures verify; root "Testbed Root CA" is not in the trust store (untrusted anchor) |
| Posture | **85**, Action required (1 critical) |
| Findings | F-0001 Critical (expired certificate, P1 82) · F-0002 Low (non-standard port 3303, P3) |
| Risk model | critical, 100% confidence; certificate validity +3.00 over a "low" baseline |
| PQC readiness | **25, Early** · HNDL exposure 100% |
| After the fix | posture 85 → 96 · risk index 100 → 25 |

**CAP-0010 · 15-pqc-readiness.pcap**

| Item | Value |
|---|---|
| Sessions | 7 SMTP, all TLS 1.3, group x25519, server `10.10.2.50:587` |
| Clients offering X25519MLKEM768 | 3 of 7 · server selected it in 0 |
| Classical posture | **100** |
| PQC readiness | **45**, Early (capped: no hybrid negotiated) |
| After "Enable hybrid PQC" | readiness **45 → 69 (Transitioning)** · hybrid sessions **0 → 3** · HNDL exposure **100% → 57.1%** |

## Likely questions

- **"Is the AI making the decisions?"** No. Every verdict comes from a deterministic, standards-cited rule. Our models add risk classification, anomaly detection and prioritisation, with explanations.
- **"Why can't you read certificates in TLS 1.3?"** TLS 1.3 encrypts the certificate message. We report that as a coverage limit, never as a pass.
- **"Do you claim to detect quantum attacks?"** No. We measure migration readiness and harvest-now, decrypt-later exposure. That's what an organisation can act on today.
- **"How was the model trained?"** On 1,600 labelled sessions generated by our testbed, then run through the same pipeline. Held-out accuracy is 98.5% and macro-F1 is 0.98. See **Risk model** in the sidebar.
