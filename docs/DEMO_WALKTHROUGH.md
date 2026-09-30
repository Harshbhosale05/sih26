# SecureMailScope — Prototype Walkthrough & Video Script

This document is the complete script for the SecureMailScope prototype video. It tells you, scene by
scene, **what to click, what the screen shows, and what to say**. Anyone with this document and the
running prototype can reproduce the demo exactly.

- **Length:** about 10–12 minutes (a 6-minute cut is given at the end)
- **Demo capture:** `CAP-0027-F-0001.pcapng` — one SMTP session, 43 packets, 8.2 KB
- **What it contains:** a STARTTLS upgrade to TLS 1.2 on a non-standard port (3303), with a server
  certificate that had **expired 35 days before** the traffic was captured

> Words in **bold quotes** are the narration. *Italic lines* are stage directions — do not read them
> aloud. `[CLICK]` marks an action on screen.

---

## Contents

1. [What the product is](#1-what-the-product-is-read-this-first)
2. [Before you record](#2-before-you-record)
3. [Video structure at a glance](#3-video-structure-at-a-glance)
4. [The script, scene by scene](#4-the-script-scene-by-scene)
5. [Numbers cheat-sheet](#5-numbers-cheat-sheet-for-this-capture)
6. [Questions viewers are likely to ask](#6-questions-viewers-are-likely-to-ask)
7. [Short 6-minute version](#7-short-6-minute-version)
8. [Troubleshooting](#8-troubleshooting)

---

## 1. What the product is (read this first)

**SecureMailScope** turns a packet capture of email traffic (SMTP, IMAP, POP3) into a cryptographic
security assessment. It is **passive**: it never connects to, scans or probes a mail server. It only
reads a capture that already exists.

Wireshark answers *"what happened in this capture?"*. SecureMailScope answers:

> *How secure is this email communication today, how prepared is it for quantum-era threats, what is
> wrong, what depends on it, how has it changed — and what is the proof?*

It is built around five capabilities. The video shows all five:

| # | Capability | Question it answers | Where in the app |
|---|---|---|---|
| 1 | **Cryptographic posture + PQC readiness** | How secure is it today, and how ready for post-quantum threats? | Overview, **Posture & PQC** |
| 2 | **Cryptographic drift** | How has the posture changed over time? | **Drift** |
| 3 | **Dependency graph + blast radius** | What depends on each weakness, and how much is affected? | **Dependencies** |
| 4 | **Evidence-backed AI** | Why did the system conclude this, and what proves it? | **Findings** (evidence panel) |
| 5 | **STARTTLS failure-point & adoption analytics** | Where does encryption upgrade succeed or fail, and who must fix it? | **STARTTLS analytics** |

Three principles run through the whole product. Repeat them in the video — they are the differentiators:

1. **Deterministic verdicts.** Every finding comes from a published rule. Machine learning adds context
   but never creates or changes a verdict.
2. **Evidence for everything.** Every finding links to the exact packets that prove it, with a
   Wireshark filter and a downloadable evidence file.
3. **Honest about blind spots.** If the capture cannot prove something, the answer is *UNKNOWN* or
   *Not assessed* — never an optimistic guess.

---

## 2. Before you record

### 2.1 Start the prototype

```bash
cd sih26
docker compose up -d          # starts database, API and dashboard
```

| Service | URL |
|---|---|
| Dashboard | http://localhost:5173 |
| API documentation | http://localhost:8000/docs |

Wait about 20 seconds, then open http://localhost:5173. The **Captures** page should load.

### 2.2 Make sure the comparison captures exist (needed for the Drift scene)

The Drift scene compares two earlier captures of the same server. Check that the **Captures** table
contains these two files:

| Capture | File | What it represents |
|---|---|---|
| `CAP-0004` | `01-secure-tls13.pcap` | The server on a good day — TLS 1.3 |
| `CAP-0005` | `03-deprecated-tls.pcap` | The same server later — TLS 1.0 |

If they are missing (e.g. after a database reset), upload them from `testbed/output/` before recording.
They are analysed automatically after upload. (Their CAP numbers may differ after a reset — use the
file names.)

> *Optional, for the richer graphs:* also have `13-enterprise-mixed.pcap` uploaded. Scenes 5 and 6
> offer an optional 20-second switch to it.

### 2.3 Screen set-up checklist

- [ ] Browser window at **1440 × 900** or larger, zoom **100%**, full screen (hide bookmarks bar)
- [ ] Choose **one theme** and keep it (the sun/moon button, top right). Light theme reads better in
      compressed video; dark theme looks more "security console". Do not switch mid-video.
- [ ] Close all other tabs; turn off notifications
- [ ] Have `CAP-0027-F-0001.pcapng` ready in a Finder window next to the browser for drag-and-drop
- [ ] Do one full dry run so every page is cached and loads instantly
- [ ] Start the recording on the **Captures** page

> **About re-uploading the same file.** SecureMailScope identifies evidence by its SHA-256 hash. If
> this exact file was uploaded before, uploading it again does not create a duplicate — it opens the
> existing assessment (`CAP-0034`) and re-runs the analysis. This is intentional (chain of custody)
> and makes a good line in the video (Scene 1).

---

## 3. Video structure at a glance

| Scene | Screen | Capability shown | Time |
|---|---|---|---|
| 0 | Title / Captures page | Introduction | 0:00 – 0:45 |
| 1 | Captures → upload | Evidence intake | 0:45 – 1:30 |
| 2 | Overview | All five, summarised | 1:30 – 2:45 |
| 3 | Posture & PQC | **#1 Posture + PQC readiness** | 2:45 – 4:30 |
| 4 | Findings → evidence panel | **#4 Evidence-backed AI** | 4:30 – 6:15 |
| 5 | STARTTLS analytics | **#5 STARTTLS failure points** | 6:15 – 7:15 |
| 6 | Dependencies | **#3 Dependency graph + blast radius** | 7:15 – 8:15 |
| 7 | Sessions | Session reconstruction | 8:15 – 8:50 |
| 8 | Drift | **#2 Cryptographic drift** | 8:50 – 10:00 |
| 9 | Report + CBOM | Deliverables | 10:00 – 11:00 |
| 10 | Closing | Summary | 11:00 – 11:40 |

---

## 4. The script, scene by scene

### Scene 0 — Introduction (0:00 – 0:45)

*Screen: the Captures page (or a title slide with the product name, if you have one).*

**"Email is still how organisations exchange sensitive information, and email security depends on
cryptography that most teams never actually see: whether STARTTLS really upgraded the connection,
which TLS version and cipher were negotiated, whether the certificate was valid, and whether any of it
will survive a future quantum computer."**

**"SecureMailScope is a passive cryptographic posture assessment platform for email. You give it a
packet capture. It reconstructs every SMTP, IMAP and POP3 session, analyses the cryptography, and
produces an assessment where every conclusion is backed by the packets that prove it. It never touches
a live server — it only reads evidence that already exists."**

**"In this demo I'll take one real capture from upload to final report."**

---

### Scene 1 — Upload the capture (0:45 – 1:30)

*Screen: Captures page. Point at the upload area.*

**"This is where evidence enters the system. It accepts PCAP and PCAPNG files, including compressed
ones."**

`[CLICK]` *Drag `CAP-0027-F-0001.pcapng` from Finder onto the dashed box* (or click the box and
choose the file).

*The box shows "Uploading…", then "Analysing…" with a spinner, then the Overview opens by itself.*

**"While it uploads, the file is hashed with SHA-256. That hash becomes the identity of the evidence:
every finding you'll see is tied back to it, and if the same file is uploaded twice we recognise it
instead of creating a duplicate record."**

**"Analysis starts automatically. In the background it indexes every TCP flow, identifies the email
sessions — by their protocol content, not just the port number — reconstructs them, parses the TLS
handshakes and certificates, and runs the detection rules."**

---

### Scene 2 — Overview (1:30 – 2:45)

*Screen: the Overview page for CAP-0034. Move the cursor to each area as you mention it.*

**"This is the assessment for our capture. At the top: the capture reference, the file, the packet
count — 43 packets — and the SHA-256 of the evidence."**

*Point at the red "Action required" banner.*

**"The first thing an analyst sees is this banner: one critical finding. We deliberately put it above
the score, because one critical exposure matters more than any average."**

*Point at the left score ring.*

**"On the left, the answer to *how secure is this communication today*: a posture score of 85 out of
100, built from six dimensions — transport security, TLS configuration, cryptographic strength,
forward secrecy, certificate security and behavioural consistency. You can already see certificate
security at zero. We'll see why in a moment."**

*Point at the right ring.*

**"On the right, the second question: *how prepared is it for quantum-era threats?* PQC readiness is
25 — 'Early'. 100% of the observed traffic uses classical key exchange, meaning it could be recorded
today and decrypted later by a quantum computer. The system already suggests the next step: move this
server to TLS 1.3."**

*Point along the four tiles.*

**"One email session, SMTP. It was encrypted — zero cleartext sessions and zero undetermined ones."**

*Point at the three bottom cards.*

**"Below: findings by severity — one critical, one low. The weaknesses with the largest blast radius.
And STARTTLS adoption — 100% of the sessions that started in plaintext successfully upgraded to TLS."**

*Point at Evidence coverage.*

**"And this is something most tools don't show: evidence coverage. Here we could observe 100% of the
session and 100% of the certificates, because this is TLS 1.2. With TLS 1.3 the certificate is
encrypted, and we would say so here instead of pretending we checked it."**

---

### Scene 3 — Posture & PQC readiness (2:45 – 4:30)  · *Capability #1*

`[CLICK]` **Posture & PQC** in the left sidebar.

**"This page answers two questions about the same handshakes: how secure is this traffic against
today's attacker, and how much of it would survive one who records it now and decrypts it with a
quantum computer later."**

#### Part A — Today: the posture score

*Point at the six dimension cards, one by one.*

**"Each dimension is scored on its own, with its own evidence coverage, its weight, and the standard
it's anchored to — RFCs and NIST guidance."**

- **"Transport security, 100: the session reached an established TLS state."**
- **"TLS configuration, 80: it negotiated TLS 1.2, not 1.3."**
- **"Cryptographic strength, 100: an AEAD cipher — AES-256-GCM."**
- **"Forward secrecy, 100: an ephemeral ECDHE key exchange."**
- **"Certificate security, zero: the one certificate we examined had already expired when the traffic
  was captured."**
- **"Behavioural consistency is *Not assessed*: with a single session there is no baseline to compare
  against. So it is excluded from the score — not given zero, which would blame the operator for our
  blind spot, and not given 100, which would invent a clean result."**

*Scroll to "How the score was calculated".*

**"And the score is not a black box. Here is the exact arithmetic: each assessed dimension times its
weight — 30, 16, 20, 15 and 0 — summing to 81, divided by the assessed weight of 0.95, gives 85.26,
rounded to 85. Behavioural consistency is listed as excluded, with the reason. An auditor can
reproduce this number by hand."**

#### Part B — Tomorrow: post-quantum readiness

*Scroll to "Tomorrow — post-quantum readiness".*

**"Now the quantum question. PQC readiness is 25, level 'Early'."**

*Point at the exposure bar and the four tiers.*

**"We classify every session by how long its confidentiality lasts. Cleartext is readable today.
Static RSA means one stolen key unlocks every recorded session. Classical ephemeral key exchange — our
session — is safe against today's attackers but falls to a future quantum computer. Only hybrid
post-quantum key exchange with ML-KEM, the NIST FIPS 203 standard, is resistant. Our one session is in
the 'classical' tier: exposed to harvest-now-decrypt-later."**

*Point at "Readiness components".*

**"The 25 comes from five published components. No hybrid PQC key exchange, no TLS 1.3, and no client
offering PQC score zero. Forward secrecy and encryption score 100. Weighted together, 25."**

*Point at "Migration plan".*

**"And instead of just a number, it produces an ordered migration plan from what is actually blocking
readiness: first move to TLS 1.3, which hybrid groups require, then enable hybrid ML-KEM key exchange.
We're careful with the framing: this is a migration-readiness measure, not a claim that a quantum
attacker exists today."**

*Point briefly at "Behavioural intelligence" at the bottom.*

**"At the bottom is the behavioural layer — each server compared against its own normal behaviour, plus
an Isolation Forest anomaly model. It needs at least 20 sessions to be meaningful, so on this capture
it says so rather than producing noise."**

---

### Scene 4 — Findings and the evidence chain (4:30 – 6:15)  · *Capability #4*

`[CLICK]` **Findings** in the sidebar.

**"Here are the findings, most severe first. Each one shows its severity, the session it came from,
how many sessions are affected, its confidence, and how it was decided — here, 'deterministic'."**

*Point at the severity tabs and the search box.*

**"You can filter by severity or search."**

`[CLICK]` **the first finding — "Certificate had already expired at capture time" (CRITICAL).**

*A panel slides in from the right.*

**"This is the evidence chain — the answer to *why did the system reach this conclusion, and what
proves it?* It reads top to bottom, like an analyst's reasoning."**

*Point at each step of the "Reasoning chain".*

1. **"What the capture shows: the evidence is at frame 20 — the server's TLS handshake, where it
   presented its certificate."**
2. **"The rule applied: the published policy rule 'certificate expired', severity critical, anchored
   to the CA/Browser Forum requirements and RFC 5280."**
3. **"Why it follows: the certificate expired on the 20th of August 2026. The traffic was captured on
   the 24th of September. That's 35 days after expiry. Note we judge validity by the capture's own
   date, not today's date — a certificate that expired after the traffic was recorded was not a
   problem at the time."**
4. **"The verdict: FAIL, critical, 100% confidence — decided by a rule on observed facts. No model was
   involved in the verdict."**

*Scroll to "Wire evidence" and "Recorded facts".*

**"Below are the raw facts we extracted from the certificate itself: subject mail.testbed.local, the
issuing CA, RSA 2048-bit key, SHA-256 signature, the validity dates, and the certificate
fingerprint."**

*Scroll to Confidence, Limits and Impact.*

**"Then what affects our confidence, what the evidence *cannot* show — here, nothing, because the
session was fully observed — and the impact: this finding caps the certificate security dimension,
so the posture reflects the worst observed state."**

*Point at "What the AI layer adds" if it is visible; otherwise say:*

**"When the anomaly model and baseline analysis have something to add, they appear here, labelled as
context only. That's what we mean by evidence-backed AI: the AI explains and prioritises, but every
verdict is traceable to a rule and to packets."**

*Scroll to "Recommended fix" and "Verify it yourself".*

**"The recommended fix: renew the certificate and automate renewal. And finally — verification. Here
is the exact Wireshark display filter, which you can copy, and this button downloads just the frames
that prove this finding, as a small evidence file. Its SHA-256 and the parent capture's SHA-256 travel
with it, so the chain of custody is preserved. Anyone can check our claim in Wireshark in ten
seconds."**

> *Optional aside (10 seconds): "In fact, the file we uploaded today is exactly such an evidence
> slice — exported from an earlier, larger capture — and it re-analyses to the same finding. The
> analysis is deterministic."*

`[CLICK]` **the ✕ to close the panel.** `[CLICK]` **the second finding — "Email service running on a
non-standard port" (LOW).**

**"The second finding is lower severity: SMTP was running on port 3303. We identified the protocol
from the server's greeting, not the port, which is how we caught it. Services on unexpected ports
often escape the TLS policies and monitoring applied to standard ports."**

`[CLICK]` **close the panel.**

---

### Scene 5 — STARTTLS failure-point & adoption analytics (6:15 – 7:15)  · *Capability #5*

`[CLICK]` **STARTTLS analytics** in the sidebar.

**"Most email starts in plaintext and upgrades with STARTTLS. That upgrade is a chain of steps, and each
step is owned by someone different. A server that never offers TLS needs a server fix. A client that
ignores the offer needs a client policy. A capability line that's been tampered with in transit points
to the network. Other tools just say 'cleartext'. We tell you where it broke and who has to fix it."**

*Point at the four tiles.*

**"Adoption: 100% — one of one session upgraded. No cleartext fallbacks, nothing stripped in transit,
no implicit TLS."**

*Point down the Upgrade funnel.*

**"The funnel shows each stage: the plaintext session opened, the server advertised STARTTLS, the
client requested it, the server accepted, the TLS handshake was negotiated, and encrypted data
flowed. Our session made it through all six stages."**

*Point at "Where upgrades stop".*

**"Here is where any failures would be classified — by the first stage they failed, with the owner of
the fix. This capture is healthy, so it shows one successful upgrade."**

*Point at the per-server table.*

**"And adoption is broken down per server and per protocol, and over the capture's timeline, so you can
see, for example, a stripping device appearing part-way through a capture."**

> *Optional (20 seconds, stronger visual): use the **Capture** dropdown in the sidebar to switch to
> `13-enterprise-mixed.pcap`, stay on STARTTLS analytics, and say:* **"On a larger enterprise capture it
> looks like this: 37 sessions, 95% adoption, and it pinpoints one session where the STARTTLS capability
> was stripped in transit — a network problem — and one where the client ignored the offer — a client
> problem."** *Then switch back to CAP-0034.*

---

### Scene 6 — Dependency graph & blast radius (7:15 – 8:15)  · *Capability #3*

`[CLICK]` **Dependencies** in the sidebar.

**"A finding tells you what's wrong. An operator's next question is: *what else depends on this?* A
weakness on a mail server reaches every client that sends mail through it, whether or not their own
session triggered the rule."**

*Point at the graph columns left to right.*

**"The graph reads left to right: clients, the mail servers they connect to, the cryptography those
servers negotiate, and the weaknesses that affect them. Here: our client 127.0.0.1 connects to the
server on port 3303, which negotiates TLS 1.2 with an ECDHE-RSA AES-256-GCM cipher. Two weaknesses
attach to that server. Servers at risk get a coloured ring."**

`[CLICK]` **the "Certificate had already expired…" card in the Blast radius panel.**

**"When I select a weakness, the graph traces everything it reaches and fades the rest."**

*Point at the three numbers on the card.*

**"Its blast radius: one session directly, one dependent client — 100% of the clients we observed —
and one server. Combined with its critical severity, that gives a blast score of 100, so it ranks
first. The non-standard port is low severity, so it scores 25."**

*Point at the method text under the list.*

**"The formula is printed right here, and we say clearly that these percentages are of the *observed*
environment: a capture is a partial view, and we don't claim more than it shows."**

`[CLICK]` **the "Crypto" tab** in the Blast radius panel.

**"The Crypto tab does the same for cryptographic primitives — for example, everything that still
depends on classical key exchange that a quantum computer could break."**

> *Optional (20 seconds): switch the capture to `13-enterprise-mixed.pcap`. The graph shows 6 servers
> and 6 weaknesses. Click "Authentication credentials transmitted without TLS" and say:* **"On a real
> estate, this is where it earns its keep — you can see at a glance which servers and clients a single
> weakness touches."** *Then switch back.*

---

### Scene 7 — Sessions (8:15 – 8:50)

`[CLICK]` **Sessions** in the sidebar.

**"Underneath everything is session reconstruction. Every email session, its client and server, its
encryption outcome and its negotiated TLS."**

`[CLICK]` **the row SMTP-0001.**

**"For each session we keep the encryption state machine with the exact frame of every transition:
frame 4 the server greeting, frame 17 STARTTLS requested, frame 18 the server accepted, frame 23 the
first encrypted data. That's how 'TLS established' is proven, not assumed. Below is every parsed
protocol event, the Wireshark filter, and a download of just this session's packets."**

`[CLICK]` **close the panel.**

---

### Scene 8 — Cryptographic drift (8:50 – 10:00)  · *Capability #2*

`[CLICK]` **Drift** in the sidebar.

**"A single capture is a photograph. Drift is what changed between photographs. SecureMailScope keeps
every analysed capture and can show how posture moves over time."**

*Point at the chart. Use the metric drop-down on the right to show "Posture score", then "TLS 1.3
share".*

**"This chart plots any metric across all analysed captures — posture score, PQC readiness, STARTTLS
adoption, TLS 1.3 share, forward secrecy and more. The chips below summarise each step: improved,
regressed, or mixed."**

*Scroll to the Baseline / Current selectors.*

`[CLICK]` **Baseline → `CAP-0004 · 01-secure-tls13.pcap`.**
`[CLICK]` **Current → `CAP-0005 · 03-deprecated-tls.pcap`.**

**"Let's compare two captures of the same mail server taken at different times."**

*Point at the four summary tiles.*

**"Verdict: regressed. Ten regressions, zero improvements."**

*Point at the Environment metrics table.*

**"The posture score fell from 100 to 65. TLS 1.3 share dropped from 100% to zero, deprecated TLS went
from zero to 100%, and AEAD ciphers from 100% to zero."**

*Point at Server configuration drift — the card for `10.10.2.50:587`.*

**"And here's the part that matters to an operator: the *same server*, matched by address and port,
went from TLS 1.3 to TLS 1.0, and from an AEAD cipher to a weak CBC cipher. Its TLS fingerprint — JA4S —
changed too, meaning a different TLS stack is now answering. That is exactly the kind of silent
misconfiguration or downgrade that a one-off scan misses."**

*Point at Findings drift.*

**"Finally, the findings that appeared: deprecated TLS and a weak cipher suite — both new since the
baseline."**

---

### Scene 9 — The report and CBOM (10:00 – 11:00)

`[CLICK]` **the Capture dropdown in the sidebar → `CAP-0034 · CAP-0027-F-0001.pcapng`**, then
`[CLICK]` **Overview**.

`[CLICK]` **the "Report" button at the top right.** *The formal report opens in a new tab.*

**"Everything we've seen is also delivered as a formal, print-ready assessment report."**

*Scroll slowly and name each section as it passes:*

1. **"An executive summary: posture 85 with 'Action required' because of the critical finding, PQC
   readiness 25, STARTTLS adoption 100%, and the findings count — followed by the key risks and the
   first action for each."**
2. **"The evidence manifest, with the SHA-256 of the capture."**
3. **"The security posture with the full calculation."**
4. **"Each finding: what was observed, why it's the conclusion, the remediation, the standards, and the
   exact frames and Wireshark filter."**
5. **"The blast radius, the STARTTLS upgrade analysis, and post-quantum readiness with the migration
   plan."**
6. **"Email policy from DNS — here the capture had no DNS, so we state that it's undetermined, not
   absent."**
7. **"The sessions with their encryption timelines, and the scope and limitations of passive
   analysis."**

`[CLICK]` **"Print / Save as PDF"** *(top right)* — show the print preview for two seconds, then
cancel.

**"It saves straight to PDF for sharing."**

*Close the report tab. Back on the Overview:*

`[CLICK]` **"CBOM".**

**"And the CBOM button exports a Cryptographic Bill of Materials in the CycloneDX 1.6 standard — an
inventory of every algorithm actually negotiated on the wire, ready for a PQC migration programme.
There's also a full REST API, so all of this can feed a SOC or SIEM."**

---

### Scene 10 — Closing (11:00 – 11:40)

*Screen: back on the Overview.*

**"So, from one packet capture, SecureMailScope answered five questions:"**

1. **"How secure is this communication today, and how ready is it for post-quantum threats?"**
2. **"How has that posture drifted over time?"**
3. **"What depends on each weakness, and how far does it reach?"**
4. **"Why did we reach each conclusion — and what is the proof?"**
5. **"Where does STARTTLS succeed or fail, and who owns the fix?"**

**"All of it passive — no server was ever touched. Every verdict is deterministic and reproducible,
every claim links to the packets that prove it, and where the evidence runs out, we say *unknown*
instead of guessing. That's SecureMailScope. Thank you."**

---

## 5. Numbers cheat-sheet for this capture

Keep this open beside you while recording. Values are for `CAP-0034` (`CAP-0027-F-0001.pcapng`).

| Item | Value |
|---|---|
| Packets / size | 43 packets · 8.2 KB |
| Captured | 24 Sep 2026, 12:37:16 UTC |
| SHA-256 | `3bef95ad9057321c8bc64708d2e5f6777799164c6eea16133403d2ee9f87eff7` |
| Sessions | 1 × SMTP · client `127.0.0.1` → server `127.0.0.1:3303` |
| Server banner | `Python SMTP 1.4.6` |
| Outcome | TLS established via STARTTLS · TLS 1.2 · `TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384` |
| State transitions | f4 greeting → f17 STARTTLS requested → f18 accepted → f23 encrypted data |
| **Posture score** | **85 / 100** — "Action required: 1 critical finding" |
| Transport security | 100 (30%) |
| TLS configuration | 80 (20%) — TLS 1.2, not 1.3 |
| Cryptographic strength | 100 (20%) — AEAD |
| Forward secrecy | 100 (15%) — ECDHE |
| Certificate security | 0 (10%) — 1 certificate, expired |
| Behavioural consistency | Not assessed (5%) — needs a baseline of ≥ 4 sessions per server |
| Calculation | 30 + 16 + 20 + 15 + 0 = 81 ÷ 0.95 = 85.26 → **85** |
| **PQC readiness** | **25 / 100 — Early** |
| PQC components | Hybrid PQC 0 · TLS 1.3 0 · Clients offering PQC 0 · Forward secrecy 100 · Encrypted 100 |
| Harvest-now-decrypt-later exposure | 100% (1 session, classical ephemeral key exchange) |
| Migration plan | 1. Move to TLS 1.3 · 2. Enable hybrid ML-KEM key exchange |
| **Findings** | 2 — 1 CRITICAL, 1 LOW, 0 unknown |
| F-0001 (CRITICAL) | Certificate expired at capture time — notAfter 20 Aug 2026, captured 24 Sep 2026 (35 days), evidence frame 20 |
| Certificate | CN=mail.testbed.local · issuer Testbed Root CA · RSA 2048 · sha256WithRSAEncryption |
| F-0002 (LOW) | SMTP on non-standard port 3303, 90% confidence |
| Blast radius | Expired cert: score 100 · Non-standard port: score 25 · 1 client, 1 server (100% of observed) |
| **STARTTLS adoption** | **100%** (1 of 1) · 0 fallbacks · 0 stripped |
| Evidence coverage | 100% of sessions observed · 1/1 certificates observable |
| Wireshark filter | `tcp.stream == 0 && frame.number >= 1 && frame.number <= 43` |
| Drift pair | `01-secure-tls13` → `03-deprecated-tls`: posture 100 → 65, TLS 1.3 → TLS 1.0 on `10.10.2.50:587`, 10 regressions |

---

## 6. Questions viewers are likely to ask

**Why is the posture 85 when there's a critical finding?**
The score is a weighted average across six dimensions, and certificate security is weighted 10%. That's
why the product shows the "Action required" banner above the score and in the report's executive summary:
a single critical exposure outranks any average. The certificate dimension itself is 0.

**Where is the "AI"?**
Two layers: a per-server behavioural baseline, and an Isolation Forest anomaly model with per-feature
attribution. They add context and prioritisation in the evidence chain. By design they never create or
change a verdict — every verdict is a published rule applied to observed packets, so it can be audited and
reproduced. The evidence chain itself is the explainability layer.

**Can it read the email content?**
No. Application data stays encrypted. The analysis covers the handshake, certificates, protocol dialogue
and flow behaviour.

**What about TLS 1.3, where the certificate is encrypted?**
The certificate can't be read passively without session keys. The product reports certificate coverage
honestly and marks the dimension "Not assessed" rather than guessing. With a key log file supplied, it can
be analysed.

**Does it scan or connect to servers?**
Never. It is entirely passive and works only on captures you already have.

**How is the score calculated — can I change it?**
The formula and every term are shown on the Posture page and in the report. Weights and severities live in
a published policy file (`backend/app/detection/policy.json`) and can be tuned without code changes.

**Why is behavioural consistency "Not assessed"?**
It needs at least four sessions to the same server to establish a baseline. With one session there's
nothing to compare against, so it's excluded rather than scored.

---

## 7. Short 6-minute version

If you need a shorter cut, keep these beats and drop the rest:

| Time | Scene | Keep |
|---|---|---|
| 0:00 – 0:30 | 0 | Two sentences: what it is, passive, evidence-backed |
| 0:30 – 1:00 | 1 | Drag-and-drop upload, "hashed for chain of custody" |
| 1:00 – 1:45 | 2 | Banner, the two rings (85 and 25), coverage |
| 1:45 – 2:45 | 3 | Certificate = 0, excluded dimension, calculation, PQC tiers + migration plan |
| 2:45 – 4:00 | 4 | Open F-0001: the four chain steps, facts, "Verify it yourself" |
| 4:00 – 4:30 | 5 | Funnel — all six stages; "we tell you who must fix it" |
| 4:30 – 5:00 | 6 | Click the expired-cert blast radius card |
| 5:00 – 5:40 | 8 | Drift compare: TLS 1.3 → TLS 1.0 on the same server |
| 5:40 – 6:00 | 9 + 10 | Open the report, one-line close |

---

## 8. Troubleshooting

| Problem | Fix |
|---|---|
| Dashboard doesn't load | `docker compose ps` — all three services should be "Up". Then `docker compose up -d`. |
| Upload says "Network error" | The API isn't ready. Wait 20 s, or check `docker compose logs api`. |
| Drift says "needs at least two analysed captures" | Upload the two comparison files from `testbed/output/` (see 2.2). |
| Numbers differ slightly from this script | The analysis was updated. Re-run analysis from the Captures page and use what the screen shows — the narration still applies. |
| Report opens without styling | Open it from the **Report** button; it is a self-contained page served by the API on port 8000. |
| Start completely fresh | `docker compose down -v` then `docker compose up -d`. This deletes all captures — re-upload the comparison files before recording. |
