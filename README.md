# SecureMailScope

**SIH26159 — AI-Assisted Cryptographic Security Posture Assessment for Secure Email Communications**
Organisation: NTRO · Category: Software · Theme: Blockchain & Cybersecurity

> A passive, evidence-driven cryptographic posture and behavioural-intelligence platform for enterprise email infrastructure. It turns raw SMTP / IMAP / POP3 packet captures into reconstructed sessions, cryptographic facts, explainable findings, per-server crypto fingerprints, prioritised remediation, and forensically traceable evidence.

---

## 0. One-line architecture

```
PCAP → Evidence Validation → Flow Reconstruction → Email Session Reconstruction →
Encryption-State Analysis → TLS/X.509 Analysis → Cryptographic Policy Engine →
Behavioural Fingerprinting → AI Anomaly & Risk Analysis → Explainable Posture Score →
Evidence-Linked Findings → Remediation → SOC Dashboard & Reports
```

---

## 1. The positioning (memorise this)

Wireshark answers: **"What happened in this packet capture?"**

SecureMailScope answers: **"What is the cryptographic security posture of this email infrastructure, which sessions are risky, why, how confident are we, what evidence proves it, and what should the admin fix first?"**

We are **not** building an AI wrapper over `tshark`. We are building the **security intelligence layer** on top of mature packet-processing tools.

Four differentiating layers:

```
1. Protocol Forensics  +  2. Cryptographic Posture  +
3. Behavioural Intelligence  +  4. Evidence-Backed Remediation
(+ 5. PQC Migration Inventory)
```

---

## 2. HARD REALITIES — read before writing any code

These are non-negotiable facts about passive TLS analysis. Several of them invalidate assumptions people make when planning this project. Design around them; do **not** discover them in week 6.

### 2.1 TLS 1.3 encrypts the certificate

In TLS 1.3, everything after `ServerHello` — `EncryptedExtensions`, `Certificate`, `CertificateVerify`, `Finished` — is encrypted with handshake traffic keys.

**You cannot extract X.509 certificates from a TLS 1.3 session in a PCAP without the keys.**

Implications:
- Certificate analysis (expiry, SAN mismatch, weak key, SHA-1 signature, chain) is **only possible for TLS ≤ 1.2**, or when an `SSLKEYLOGFILE` is supplied.
- The more modern the infrastructure, the *less* we can see. This is the correct and honest behaviour — and we turn it into a feature (see **Evidence Coverage Score**, §4.5).
- Our testbed must capture with `SSLKEYLOGFILE` so we can demo full certificate analysis on TLS 1.3 sessions, and clearly label those sessions as "keylog-assisted".

What we **can** always see in TLS 1.3: ClientHello (version list, cipher suites, supported groups, key shares, signature algorithms, ALPN, SNI), ServerHello (chosen version, chosen cipher, chosen group), record sizes, timing, and the plaintext SMTP/IMAP/POP3 pre-STARTTLS conversation.

### 2.2 Encrypted Client Hello (ECH)

Where ECH is deployed, SNI is not visible. Handle `sni = UNKNOWN (ECH)` as a first-class state, never as "no SNI".

### 2.3 TShark and Zeek already do the hard parts

Do **not** write a TCP reassembler, a TLS parser, or an X.509 parser. Zeek and TShark do full stream reassembly, handle retransmits/out-of-order/duplicates, and dissect TLS. Our custom code starts *after* that.

### 2.4 Zeek's email analyser coverage is uneven

- `smtp.log` — good, mature SMTP analyser.
- POP3 — analyser exists but is limited.
- IMAP — Zeek's IMAP analyser essentially only detects STARTTLS.

So: **Zeek for SMTP + TLS + X.509 + DNS + conn**, and **our own lightweight line-protocol parser (over TShark-reassembled streams) for IMAP and POP3 pre-TLS command sequences.** That's a few hundred lines, not a protocol stack.

> **Decision (Phase 0): TShark-first, Zeek deferred to Phase 1 as an optional accelerator.**
> Zeek's value is *speed* on large captures, not capability — TShark can produce everything Zeek gives us, just slower. Making Zeek a day-one hard dependency buys nothing for captures under a few hundred MB and costs us an arm64 image risk on Apple Silicon dev machines. Both sit behind one `EngineRunner` interface in `app/engines/`, so adding Zeek later is a new implementation, not a refactor. Build for correctness first; add the accelerator when a capture is actually slow.

### 2.5 A 500k-packet capture will kill naive `tshark -T json`

`tshark -T json` on a large capture produces gigabytes and is slow. Use a **two-pass architecture** (§3): a cheap Zeek pass to index all flows, then targeted deep parsing only on candidate email flows.

### 2.6 Modern OpenSSL refuses to speak TLS 1.0/1.1

To generate "deprecated TLS" testbed scenarios you need `@SECLEVEL=0`, `MinProtocol=TLSv1`, and likely an older OpenSSL container image. Budget time for this; it always takes longer than expected.

### 2.7 A capture is a partial view of reality

Truncated captures, one-direction captures, mid-session starts, snaplen truncation. **`UNKNOWN` must be a first-class verdict alongside `PASS` / `FAIL`.** Never fabricate.

### 2.8 An anomaly is not an attack

ML output is "deviating behaviour", never "ATTACK CONFIRMED". This scientific honesty is a scoring advantage with technical judges, not a weakness.

---

## 3. Architecture

### Two-pass pipeline

```
                      ┌──────────────────────┐
                      │  PCAP / PCAPNG (.gz) │
                      └──────────┬───────────┘
                                 ▼
   PASS 0   ┌─────────────────────────────────────────┐
  Evidence  │ capinfos + SHA-256 + size + time range  │
            │ → immutable Evidence Manifest           │
            └────────────────────┬────────────────────┘
                                 ▼
   PASS 1   ┌─────────────────────────────────────────┐
   Index    │ Zeek  → conn.log ssl.log x509.log       │
  (cheap,   │         smtp.log dns.log files.log      │
   whole    │ Identify candidate email flows via      │
   capture) │ port + protocol signature + behaviour   │
            └────────────────────┬────────────────────┘
                                 ▼
   PASS 2   ┌─────────────────────────────────────────┐
   Deep     │ TShark targeted at candidate streams:   │
  (only     │  - reassembled SMTP/IMAP/POP3 command   │
   email    │    streams (line-protocol parser)       │
   flows)   │  - full TLS handshake record detail     │
            │  - certificate DER extraction (≤TLS1.2) │
            └────────────────────┬────────────────────┘
                                 ▼
            ┌─────────────────────────────────────────┐
            │ Email Session Reconstruction            │
            │ + Encryption State Machine              │
            └────────────────────┬────────────────────┘
                                 ▼
            ┌─────────────────────────────────────────┐
            │ Crypto & X.509 Analyser (python-crypto) │
            │ + JA3/JA3S/JA4 fingerprint computation  │
            └────────────────────┬────────────────────┘
                                 ▼
            ┌─────────────────────────────────────────┐
            │ Feature Extraction Engine               │
            └──────────┬──────────────────┬───────────┘
                       ▼                  ▼
          ┌────────────────────┐  ┌────────────────────┐
          │ Deterministic      │  │ AI/ML Engine       │
          │ Policy Engine      │  │ anomaly + priority │
          │ (YAML rules)       │  │ (explainable)      │
          └─────────┬──────────┘  └─────────┬──────────┘
                    └────────────┬──────────┘
                                 ▼
            ┌─────────────────────────────────────────┐
            │ Risk & Posture Engine (6 dimensions)    │
            │ + Evidence Coverage Score               │
            └────────────────────┬────────────────────┘
                                 ▼
            ┌─────────────────────────────────────────┐
            │ Findings + Prioritised Remediation      │
            └──────┬───────────────┬──────────┬───────┘
                   ▼               ▼          ▼
            ┌───────────┐  ┌────────────┐  ┌──────────────┐
            │ SOC       │  │ Reports    │  │ Machine      │
            │ Dashboard │  │ JSON/HTML/ │  │ exports:     │
            │           │  │ PDF        │  │ CBOM · OCSF  │
            └───────────┘  └────────────┘  └──────────────┘
```

### Encryption State Machine

Every email session is driven through an explicit FSM:

```
UNKNOWN → TCP_CONNECTED → PLAINTEXT_EMAIL → TLS_REQUESTED
        → TLS_NEGOTIATION → TLS_ESTABLISHED → ENCRYPTED_APPLICATION_DATA
```

Terminal/abnormal states we must model explicitly:

| State | Meaning |
|---|---|
| `IMPLICIT_TLS` | Connected directly on 465/993/995, no plaintext phase (RFC 8314 preferred) |
| `STARTTLS_ADVERTISED_NOT_USED` | Server offered it, client never asked |
| `STARTTLS_NOT_ADVERTISED` | Server never offered it on a STARTTLS-capable port |
| `STARTTLS_REJECTED` | Client asked, server refused (`454`, `BAD`, `-ERR`) |
| `STARTTLS_NEGOTIATION_FAILED` | TLS started, handshake never completed |
| `PLAINTEXT_AFTER_FAILURE` | Fell back to cleartext and kept sending — highest severity |
| `PLAINTEXT_THROUGHOUT` | Never attempted encryption |
| `TRUNCATED` | Capture ends mid-session — verdict `UNKNOWN` |

Protocol note: SMTP and IMAP use `STARTTLS`; POP3 uses **`STLS`**. Build the upgrade-command mapping as data, not hardcoded strings.

---

## 4. The seven signature features

Every one of these is grounded in a real-world system or standard. This is what separates us from "dashboard over tshark".

### 4.1 STARTTLS Stripping Detector — *cross-session capability differential*

**Real-world:** STARTTLS stripping is an actively observed attack. Network middleboxes and some ISPs have been documented rewriting the `250-STARTTLS` line in EHLO responses to garbage (e.g. `250-XXXXXXXA`) so the client never upgrades, silently downgrading mail to cleartext. This drove EFF's STARTTLS Everywhere and later MTA-STS (RFC 8461).

**Our detection (deterministic, not AI):** we hold a per-server capability profile across *all* sessions in the capture.

```
mail01.corp.local :25
  session SMTP-0012  EHLO → 250-STARTTLS advertised  ✓
  session SMTP-0119  EHLO → 250-STARTTLS advertised  ✓
  session SMTP-0431  EHLO → capability line MANGLED  ✗   ← evidence of on-path stripping
```

Detected signals:
- Capability present in some sessions, absent/corrupted in others, same server + port.
- EHLO response containing non-ASCII / obviously rewritten capability tokens.
- `STARTTLS` advertised but the server rejects the command when issued.
- Same-length replacement strings (classic in-place rewrite signature).

This produces a **CRITICAL finding with hard evidence** and is far more compelling than "TLS 1.0 detected". It is also something Wireshark will never tell you, because it requires cross-session correlation.

### 4.2 DNS-Correlated Email Policy Audit

**Real-world:** NIST SP 800-177r1 (Trustworthy Email), RFC 8461 (MTA-STS), RFC 7672 (DANE for SMTP), RFC 8460 (TLS-RPT). Major providers enforce these.

Most PCAPs of real mail traffic contain the DNS lookups that preceded the SMTP connections. We mine `dns.log` from the same capture for:

| Record | What we check |
|---|---|
| `MX` | Which hosts the sender resolved, and whether it then connected to them |
| `_mta-sts.<domain> TXT` | Did the sender **query** MTA-STS policy at all? Is one published? |
| `_smtp._tls.<domain> TXT` | Is TLS-RPT reporting configured? |
| `_25._tcp.<mx> TLSA` | Is DANE deployed? Did the sender query it? |
| `SPF / DKIM / DMARC TXT` | Baseline email-authentication posture |

Then the killer correlation: **did the observed TLS behaviour comply with the policy that was actually published and fetched?** A sender that queried MTA-STS `mode=enforce` and then sent in cleartext is a policy violation with proof from a single capture.

No other team will do this. It costs us one extra Zeek log.

### 4.3 PQC Readiness & Cryptographic Bill of Materials (CBOM)

**Real-world:** Hybrid post-quantum key exchange is *live in production today* — browsers and servers negotiate `X25519MLKEM768` (and earlier `X25519Kyber768Draft00`). It is visible in the ClientHello `supported_groups` and `key_share` extensions, in cleartext, in every capture. CNSA 2.0 sets migration deadlines; NIST has standardised ML-KEM (FIPS 203) and ML-DSA (FIPS 204).

So we can answer, passively and factually:

```
PQC READINESS — mail01.corp.local
  Clients offering hybrid PQC key exchange      12 / 84  (14%)
  Server selecting hybrid PQC                    0 / 84  ( 0%)  ← server not PQC-capable
  Classical key-exchange dependency            ECDHE (X25519, secp256r1)
  Classical authentication dependency          RSA-3072, ECDSA P-256
  Harvest-now-decrypt-later exposure           HIGH (long-lived mail content)
```

**Export it as a CycloneDX CBOM** (Cryptographic Bill of Materials, CycloneDX 1.6+). That is a real, current, enterprise-relevant standard for crypto inventory and PQC migration planning. Shipping a standards-compliant CBOM from a PCAP is a genuinely novel artefact.

We say: *"here is your inventory of classical public-key cryptography and your migration exposure"*. We never say *"we detect quantum attacks"*.

### 4.4 Cryptographic Behaviour Fingerprint — built on JA3/JA3S/JA4

**Real-world:** JA3/JA3S (Salesforce) and JA4+ (FoxIO) are the industry-standard TLS fingerprints used across SOC tooling and threat intel. Zeek and Suricata both support them.

Don't invent a fingerprint format — compute the standard ones (`JA3`, `JA3S`, `JA4`, `JA4S`) and build our **server crypto profile** on top:

```
MAIL-SERVER-01 · cryptographic behaviour profile  (n = 84 sessions)
  TLS versions      1.3 → 92%   1.2 → 8%
  Cipher suites     AES_256_GCM_SHA384 · CHACHA20_POLY1305_SHA256
  Key exchange      X25519 (98%)  secp256r1 (2%)
  JA4S              t130200_1301_a56c5b993250
  Certificate       RSA-3072 / SHA-256 / issuer "Corp Internal CA"
  Forward secrecy   yes (100%)
  Median handshake  38 ms
```

Any session deviating from its server's established profile is flagged **Cryptographic Behaviour Deviation** with the exact dimension that deviated. *This is the honest, useful job for ML* — and it's what makes the AI component more than decoration.

> Licensing note: JA3/JA3S are open. Core `JA4` is BSD-3-Clause; other JA4+ variants carry FoxIO licence terms. Stick to JA3/JA3S/JA4/JA4S and record the licences in `NOTICE`.

### 4.5 Evidence Coverage Score — honesty as a feature

Every dimension of the posture score is reported alongside how much of it we could actually observe.

```
Certificate Security      94/100   ⓘ coverage 31%
                                     (26 of 84 sessions had an observable certificate;
                                      58 used TLS 1.3 — handshake encrypted)
```

This kills the biggest weakness of every competing submission: a confident-looking score computed from invisible data. Judges with real networking background will notice. Every finding carries `PASS | FAIL | UNKNOWN` plus `evidence_completeness`.

### 4.6 Credential Exposure Detector — findings without leaking secrets

**Real-world:** the highest-impact thing you can find in mail traffic is `AUTH LOGIN` / `AUTH PLAIN` / POP3 `USER`/`PASS` / IMAP `LOGIN` sent before TLS. Base64 is not encryption. This is an immediate, unambiguous credential compromise.

We detect **that it happened** and never store the credential:

```json
{
  "finding_id": "F-0001",
  "severity": "CRITICAL",
  "title": "SMTP AUTH credentials transmitted in cleartext",
  "mechanism": "AUTH LOGIN issued before STARTTLS",
  "username_redacted": "j****@corp.local",
  "credential_sha256_prefix": "a3f19b",
  "credential_length": 14,
  "credential_stored": false,
  "affected_accounts": 3,
  "evidence": { "session_id": "SMTP-0431", "frames": [88214, 88219] }
}
```

The SHA-256 prefix lets an admin confirm which credential without us ever persisting it. That design choice *is* the pitch on privacy.

### 4.7 Evidence-linked, analyst-verifiable findings

Every finding ships three things that make it independently verifiable:

1. **Full evidence chain** — `Report → Finding → Session → TCP stream → Frame range → PCAP SHA-256`
2. **A ready-to-paste Wireshark display filter**, e.g.
   `tcp.stream == 1042 && frame.number >= 88200 && frame.number <= 88260`
3. **A one-click sliced mini-PCAP** for that session (`tshark -w` on the stream), hash-linked to the parent capture.

An analyst can open our slice in Wireshark and confirm the finding in ten seconds. Nobody argues with that in a demo.

**Plus, stretch:** map findings to **OCSF** (Open Cybersecurity Schema Framework) `Detection Finding` / `Compliance Finding` classes so output drops straight into a modern SIEM. Real integration beats a mock "SIEM tab".

---

## 5. Where AI genuinely belongs (and where it must not)

### The inviolable rule

```
           ✗  PCAP → AI → security verdict
           ✓  PCAP → facts → deterministic rules → AI adds context → prioritisation
```

If it's computable, compute it. `capture_time > cert.not_after` is arithmetic, not machine learning. Using ML for it is a bug.

### AI job 1 — Handshake anomaly detection (`IsolationForest`)
Unsupervised, trained on the mostly-normal traffic in the capture itself + testbed normals. Input: the feature vector in §6. Output: anomaly score + **per-feature attribution** so we can say *which* dimension was anomalous. Start here; it works with zero labels.

### AI job 2 — Finding prioritisation (learning-to-rank / gradient boosting)
Only after we have a labelled testbed corpus. Features: severity, confidence, affected-session count, server criticality, baseline deviation, exposure, credential involvement.

### AI job 3 — LLM-generated vendor-specific remediation
This is the highest-value, lowest-risk AI use and nobody else will do it. Given a finding plus detected server software (from SMTP banner / IMAP `CAPABILITY` greeting), generate the **actual config change**:

```
Finding: Deprecated TLS 1.0 accepted on submission (587)
Detected: Postfix 3.6.x

  # /etc/postfix/main.cf
- smtpd_tls_mandatory_protocols = !SSLv2, !SSLv3
+ smtpd_tls_mandatory_protocols = >=TLSv1.2
+ smtpd_tls_mandatory_ciphers = high
+ tls_high_cipherlist = ECDHE+AESGCM:ECDHE+CHACHA20

  Rationale: NIST SP 800-52 Rev. 2 §3.1 — TLS 1.0/1.1 shall not be used.
  Verify:  openssl s_client -starttls smtp -tls1 -connect mail01:587   # must fail
```

Ground the LLM in a small RAG corpus (RFC 8314, RFC 8461, RFC 7672, NIST SP 800-52r2, SP 800-177r1, Mozilla TLS config guidelines) so every recommendation carries a citation. **The LLM writes prose and config, never verdicts.**

### AI job 4 — Natural-language incident narrative
Turn the session timeline into an analyst-readable paragraph for the report. Cosmetic but demos extremely well.

### Explainability requirement

Never render "AI says HIGH RISK". Always:

```
HIGH RISK  (composite 0.87)
  + Deprecated TLS version               deterministic   weight 0.30
  + No forward secrecy                   deterministic   weight 0.25
  + Certificate expires in 3 days        deterministic   weight 0.15
  + Deviates from server crypto profile  ML anomaly 0.91 weight 0.20
  + 3 other sessions affected            correlation     weight 0.10
Evidence → SMTP-1042 · 10.10.2.15→10.10.2.50 · frames 88200-88260 · 10:32:01.441
```

---

## 6. Feature vector (ML input)

```
protocol, port_class(implicit_tls|starttls|plaintext), encryption_state,
tls_version_offered[], tls_version_negotiated, cipher_suite, key_exchange_alg,
group, auth_alg, aead, hash, forward_secrecy, ja3, ja3s, ja4, ja4s,
extension_count, alpn, sni_present, pqc_group_offered, pqc_group_selected,
cert_observable, cert_key_alg, cert_key_bits, cert_sig_alg, cert_validity_days,
cert_days_to_expiry, cert_san_match, chain_depth,
starttls_advertised, starttls_requested, starttls_succeeded, downgrade_observed,
cleartext_auth_observed, handshake_duration_ms, rtt_estimate_ms,
session_duration_s, packet_count, bytes_c2s, bytes_s2c,
server_id, server_session_count, baseline_deviation_score, evidence_completeness
```

---

## 7. Posture scoring — anchored, not invented

Six dimensions, configurable weights, every one reported with coverage:

| Dimension | Anchored to |
|---|---|
| Cryptographic Strength | NIST SP 800-52r2, Mozilla TLS "Modern/Intermediate/Old" |
| TLS Configuration | RFC 8996 (TLS 1.0/1.1 deprecated), RFC 8446 |
| Certificate Security | CA/Browser Forum Baseline Requirements |
| STARTTLS / Transport Security | RFC 3207, RFC 8314, RFC 8461 |
| Forward Secrecy | NIST SP 800-52r2 |
| Behavioural Consistency | our own baseline model (clearly labelled as such) |

Call it the **SecureMailScope Posture Score** and always expose the exact factor breakdown. Never present it as absolute industry truth. Ship the weights as an editable YAML so a judge can change them live — that alone demonstrates it isn't a magic number.

---

## 8. Data model (PostgreSQL)

```
captures(capture_id, filename, sha256, format, size_bytes, packet_count,
         link_type, start_time, end_time, snaplen, truncated, uploaded_by, uploaded_at)

flows(flow_id, capture_id, src_ip, src_port, dst_ip, dst_port, proto,
      first_frame, last_frame, packets, bytes_c2s, bytes_s2c, start_time, end_time)

sessions(session_id, capture_id, flow_id, protocol, port_class, encryption_state,
         state_transitions jsonb, server_identity, banner, evidence_completeness)

tls_handshakes(session_id, version_offered[], version_negotiated, cipher_suite,
               key_exchange, group, auth_alg, aead, hash, forward_secrecy,
               ja3, ja3s, ja4, ja4s, alpn, sni, sni_status, extensions jsonb,
               pqc_groups_offered[], pqc_group_selected, handshake_duration_ms,
               handshake_complete, cert_observable, cert_unobservable_reason)

certificates(certificate_id, session_id, chain_index, subject, issuer, san[],
             serial, valid_from, valid_to, public_key_alg, public_key_bits,
             signature_alg, is_ca, chain_status, fingerprint_sha256, der_ref)

dns_observations(capture_id, qname, qtype, rdata, is_mta_sts, is_tlsa,
                 is_spf, is_dmarc, is_tlsrpt, frame)

findings(finding_id, capture_id, session_id, severity, category, title,
         description, verdict PASS|FAIL|UNKNOWN, confidence, detection_method,
         evidence jsonb, wireshark_filter, frame_range int4range,
         affected_sessions, standard_refs[], recommendation_id)

server_profiles(server_id, capture_id, host, port, session_count, profile jsonb,
                ja4s_set[], established_at)

baseline_deviations(session_id, server_id, dimension, expected, observed, score)

risk_scores(capture_id, dimension, score, coverage_pct, factors jsonb)

recommendations(recommendation_id, finding_id, priority, action, config_diff,
                detected_software, rationale, standard_ref, verification_command)

audit_log(id, actor, action, target, ts)
```

---

## 9. Tech stack

| Layer | Choice | Why |
|---|---|---|
| Packet indexing | **Zeek** | Fast C++ whole-capture pass; conn/ssl/x509/smtp/dns/files logs |
| Deep packet parsing | **TShark** (targeted) | Reassembled streams, full TLS record detail |
| Custom packet work | **Scapy / dpkt** | Only where Zeek+TShark fall short |
| Certificates | **`cryptography`** (Python) | X.509 parsing and validation |
| Backend | **Python 3.11 + FastAPI** | Networking/security/ML ecosystem |
| Jobs | **Celery + Redis** (or FastAPI BackgroundTasks for MVP) | Analysis is long-running |
| DB | **PostgreSQL 16** (JSONB) | Relational + flexible evidence blobs |
| ML | **scikit-learn**, later **XGBoost** | No deep learning. None. |
| LLM | Claude API | Remediation text + config diffs only |
| Frontend | **React + TypeScript + Vite + Tailwind** | Standard, fast |
| Charts | **Recharts** | Enough for everything we need |
| Timeline/graph | **React Flow** or plain SVG | Don't over-engineer |
| PDF | **WeasyPrint** (HTML → PDF) | One template renders both HTML and PDF |
| Packaging | **Docker Compose** | Zeek/TShark install pain solved once |

Everything ships as `docker compose up`. Zeek and TShark are painful to install natively on macOS — containerise on day one. Nobody on the team should be installing Zeek by hand.

---

## 10. Repository layout

```
securemailscope/
├── backend/
│   └── app/
│       ├── api/                  # FastAPI routers
│       ├── models/               # SQLAlchemy + Pydantic
│       ├── pcap/                 # loader, validator, metadata, slicer
│       ├── engines/              # zeek_runner.py, tshark_runner.py
│       ├── flows/                # flow indexing, candidate selection
│       ├── protocols/            # smtp.py imap.py pop3.py state_machine.py
│       ├── tls/                  # handshake.py certificate.py crypto.py fingerprint.py
│       ├── dns/                  # mta_sts.py dane.py spf_dmarc.py
│       ├── detection/
│       │   ├── policy/           # *.yaml rule definitions
│       │   ├── engine.py
│       │   ├── starttls_stripping.py
│       │   ├── downgrade.py
│       │   └── credential_exposure.py
│       ├── ml/                   # features.py anomaly.py priority.py explain.py
│       ├── posture/              # scoring.py coverage.py simulator.py
│       ├── pqc/                  # readiness.py cbom.py
│       ├── reports/              # json.py html.py pdf.py ocsf.py
│       └── llm/                  # remediation.py narrative.py rag/
├── frontend/
│   ├── src/pages/                # Upload Overview Sessions Findings Servers Reports
│   ├── src/components/
│   └── src/charts/
├── ml/{datasets,training,models}/
├── testbed/
│   ├── servers/                  # aiosmtpd / dovecot configs
│   ├── certs/                    # cert generation scripts
│   ├── scenarios/                # scenario-NN.yaml
│   └── capture.sh                # run scenario → labelled pcap + keylog
├── sample_pcaps/
├── docs/
├── docker-compose.yml
└── README.md
```

---

## 11. Dataset strategy

**Do not wait for NTRO to hand you a capture.** Build a controlled lab that produces labelled PCAPs on demand — this is our dataset, our test suite, and our demo material.

Full detail in [`testbed/README.md`](testbed/README.md). Three tiers:

| Tier | Method | Covers | Status |
|---|---|---|---|
| **1 — Synthetic** | Hand-built packet bytes in pure Python. No Docker, no root, no network. | Protocol state machines, STARTTLS/STLS, stripping, downgrade, cleartext creds, negotiated TLS version/cipher/groups, PQC offers, truncation | **Built — 12 scenarios generating** |
| **2 — Docker testbed** | Real servers + real TLS + `tcpdump` | Real certificates, real key exchange, keylog-assisted TLS 1.3 | Not started |
| **3 — Public captures** | Wireshark SampleCaptures, malware-traffic-analysis.net | Robustness only — never training, never accuracy claims | Ongoing |

Tier 1 is deliberately the larger share. For the plaintext phase — which carries our highest-value findings — synthesising bytes is *better* than capturing them: ground truth is exact (the truth file names the frame number carrying the mangled capability line), output is deterministic, and it runs in CI. Tier 2 exists only for what tier 1 genuinely cannot fake: real X.509.

### Tier 2 approach: scripted servers over full mail stack

Fighting Postfix/Dovecot configs to force TLS 1.0 and weak ciphers burns days. Instead:

- **SMTP:** `aiosmtpd` with a custom `ssl.SSLContext` per scenario — full control over min/max TLS version, cipher list, cert.
- **IMAP/POP3:** ~150-line asyncio servers implementing just enough (`CAPABILITY`/`CAPA`, `STARTTLS`/`STLS`, `LOGIN`/`USER`/`PASS`, `LOGOUT`/`QUIT`). We only need the pre-TLS conversation and the handshake to be real.
- **Certificates:** generated by script — valid, expired, not-yet-valid, wrong CN/SAN, 1024-bit RSA, SHA-1 signed, self-signed, incomplete chain.
- **Capture:** `tcpdump` in the same Docker network, with `SSLKEYLOGFILE` exported for the keylog-assisted scenarios.
- Also run a **Postfix + Dovecot** scenario for realism — but only one or two, not all ten.

### Scenario matrix (each → labelled PCAP)

| # | Scenario | Label |
|---|---|---|
| 1 | TLS 1.3, AES-256-GCM, X25519, valid cert | `secure` |
| 2 | TLS 1.2, ECDHE-RSA-AES256-GCM, valid cert | `acceptable` |
| 3 | TLS 1.0 / 1.1 accepted | `deprecated_tls` |
| 4 | Expired certificate | `expired_cert` |
| 5 | Hostname / SAN mismatch | `cert_mismatch` |
| 6 | 1024-bit RSA key, SHA-1 signature | `weak_crypto` |
| 7 | Static RSA key exchange (no PFS) | `no_pfs` |
| 8 | STARTTLS advertised, client never uses it | `starttls_not_enforced` |
| 9 | STARTTLS capability stripped by on-path proxy | `starttls_stripping` |
| 10 | STARTTLS requested → handshake fails → cleartext continues | `downgrade_fallback` |
| 11 | `AUTH PLAIN` before STARTTLS | `credential_exposure` |
| 12 | Implicit TLS on 465/993/995 | `secure_implicit` |
| 13 | Mixed realistic enterprise traffic, 8 servers, 200+ sessions | `enterprise_normal` |
| 14 | Scenario 13 + 3 injected anomalies | `enterprise_anomalous` |
| 15 | Hybrid PQC key exchange offered (X25519MLKEM768) | `pqc_ready` |
| 16 | Truncated / mid-session capture | `incomplete_evidence` |

Scenarios 13 and 14 are the demo captures and the ML training set. Scenario 16 exists purely to prove we output `UNKNOWN` correctly — build it early.

Also grab public captures (Wireshark sample captures, malware-traffic-analysis.net) as unlabelled robustness tests. Our parser must not crash on real-world garbage.

---

## 12. Roadmap

Strict ordering. **The deterministic forensic engine must fully work before any AI is added.** A working Phase 1–3 with no AI beats a broken Phase 1–5.

### Phase 0 — Foundations (week 1) — *in progress*
`docker compose` with TShark + Postgres + FastAPI + React skeleton. Upload endpoint, SHA-256, `capinfos` metadata, Evidence Manifest persisted. Testbed generating labelled PCAPs.
**Done when:** upload a PCAP, see its manifest and packet count in the UI.

| Item | Status |
|---|---|
| Repo structure, Docker Compose, Makefile | done |
| API image (Python 3.11 + tshark/capinfos/editcap, non-root) | done, unbuilt |
| Evidence Manifest model + streaming upload + sha256 + content-hash dedup | done, untested |
| Magic-byte container validation (pcap/pcapng/gzip) | done, untested |
| `capinfos` metadata extraction with snaplen-truncation detection | done, untested |
| Safe tool runner (argv lists, timeouts, no shell) | done, untested |
| **Tier 1 testbed — 12 labelled scenarios** | **done, verified** |
| Stack build + end-to-end upload | blocked on Docker |
| React skeleton | not started |

### Phase 1 — Protocol forensics — *complete*
TShark two-pass, candidate-flow selection, stream reassembly with frame provenance, SMTP/IMAP/POP3 parsers, Encryption State Machine, session reconstruction, credential-exposure evidence.

**Done when:** every scenario classifies into the correct encryption state, including `TRUNCATED → UNKNOWN`. → **12/12 passing** (`python3 scripts/validate.py`).

Key implementation notes:
- Reassembly is ours, not tshark's: `tcp.desegment_tcp_streams:FALSE` plus per-frame `tcp.payload`, reordered by sequence. tshark's own reassembly hands back one joined blob and destroys the byte→frame mapping — without that mapping there is no evidence link, which is the product.
- Wireshark 4.x display filters need **comma**-separated set elements (`tcp.stream in {0, 1}`). Space-separated is a silent parse error on 4.x and was valid in 3.x.
- A **mangled capability is not an advertisement.** A stripped session ends in `STARTTLS_NOT_ADVERTISED`, because from the client's view STARTTLS never was offered — that is what the attack achieves. The ground truth originally said otherwise and the implementation was right.
- `IMPLICIT_TLS` is its own terminal state, not collapsed into `TLS_ESTABLISHED`: "never had a plaintext phase" is a distinct and better posture.

### Phase 2 — TLS parameters — *complete (X.509 deferred to tier-2 testbed)*
Handshake extraction, version/cipher/group decomposition (TLS 1.2 and 1.3 handled *separately*), JA3/JA3S/JA4/JA4S, PQC group detection, `cert_unobservable_reason`.
**Done when:** TLS parameters extract correctly and TLS 1.3 sessions report "certificate not observable". → **12/12 passing**, all TLS finding categories live.

Traps this phase exists to avoid, each one now covered by a fixture:
- **TLS 1.3's negotiated version is not `legacy_version`.** RFC 8446 pins that field to 0x0303 for middlebox compatibility and carries the real version in `supported_versions`. Reading the legacy field reports every TLS 1.3 session as TLS 1.2 — silently understating the posture of the most modern infrastructure.
- **TLS 1.3 suites have no key exchange or auth in the name.** `TLS_AES_256_GCM_SHA384` decomposes to cipher + hash only; kex comes from `key_share`, auth from the certificate. Parsing it with the TLS 1.2 model yields "key exchange: AES".
- **GREASE (RFC 8701) must be stripped before fingerprinting.** Clients randomise those values per connection, so a JA3 computed with them included changes every session and fingerprints nothing.
- **Python's `idna` codec rejects any `errors=` other than `strict`.** `name.decode("idna", errors="replace")` raises and, inside a try block, silently loses every SNI. Found in testing — JA4 was reporting `i` (no SNI) on sessions that plainly had one.

X.509 parsing is deferred, not skipped: synthetic captures have no Certificate message, and TLS 1.3 encrypts it anyway. It lands with the tier-2 Docker testbed and the keylog-assisted path.

### Phase 3 — Policy engine & findings — *complete (except PCAP slicing)*
Config-driven rules (`app/detection/policy.json`), PASS/FAIL/**UNKNOWN** verdicts, severity ranking, STARTTLS stripping detector, credential exposure detector, downgrade detector, evidence links + Wireshark filters.
**Done when:** every scenario produces its expected finding with an evidence link. → **12/12 passing**, including frame-level evidence accuracy and zero findings above INFO on the clean controls.

Implemented categories: `cleartext_credential_exposure`, `starttls_stripping`, `starttls_downgrade_fallback`, `starttls_not_advertised`, `starttls_advertised_not_used`, `cleartext_mail_transaction`, `incomplete_evidence`, `protocol_port_mismatch`.
Pending Phase 2 (need TLS parameter extraction): `deprecated_tls_version`, `weak_cipher_suite`, `no_forward_secrecy`. Pending Phase 6: `pqc_server_not_ready`.

**Stripping detector confidence is tiered by baseline strength**, because the strength of the claim genuinely differs:

| Baseline | Confidence | Meaning |
|---|---|---|
| Same `server:port` | 0.9 | Compared against the server's own normal behaviour |
| Same host, other port | 0.7 | Host advertises STARTTLS elsewhere — 25 and 587 can legitimately differ |
| None | 0.5 | Suspicious shape, unprovable from this capture |

Still to do: per-finding PCAP slicing via `editcap` (the "download the evidence" button).

### Phase 4 — Dashboard — *complete (reports pending)*
SOC dashboard at `http://localhost:8000/`: evidence manifest, stat tiles, encryption-posture bar, evidence coverage, findings with full evidence chains, **server capability profiles**, filterable session table, and a session detail drawer with the encryption timeline and negotiated cryptography.

**Stack decision: a single self-contained HTML file served by FastAPI — no React, no Vite, no build step.** The README originally specified React+TS+Tailwind; that buys component reuse we do not yet need and costs a full node toolchain, ~200 MB of `node_modules`, a second dev server and CORS setup. One static file loads instantly, iterates with a browser refresh, and looks identical in a demo. Nothing here blocks migrating later — the API is the contract, and the dashboard only consumes JSON.

Visualisation follows the `dataviz` method: headline numbers are stat tiles rather than gratuitous charts, encryption states use the **reserved status palette** (they are states, not series) always paired with their text label so colour never carries meaning alone, the composition bar keeps 2px surface gaps, and the palette is the validated default with dark mode declared under both the OS media query and an explicit theme stamp.

Still to do: JSON/HTML/PDF report export, and per-finding PCAP slicing via `editcap`.

### Phase 5 — Posture & behavioural intelligence — *complete*
Six-dimension posture score with per-dimension coverage, per-server cryptographic fingerprints, deterministic baseline deviation, and Isolation Forest anomaly detection with per-feature attribution.
**Done when:** deviations surface with a stated deviating dimension. → **12/12 still passing**; enterprise capture scores **71**, with `Certificate Security` reported NOT ASSESSED rather than guessed.

Three design decisions worth keeping:

- **A dimension with no coverage is excluded from the overall score, never scored.** Scoring it 0 punishes the operator for our blind spot; scoring it 100 invents a clean result. `Certificate Security` is normally NOT ASSESSED because TLS 1.3 encrypts the certificate — the score says so and drops that weight.
- **Severe findings cap their dimension.** A percentage-of-sessions metric let 35 healthy sessions dilute one cleartext credential exposure to a 95/100 transport score. Posture is about *worst observed state*, not average state, so a CRITICAL finding caps its dimension at 40 and the cap is shown inline.
- **The anomaly model refuses to run below 20 sessions** and says why. Isolation Forest on a dozen points makes every point look isolated — confident noise. Deterministic rules and baseline deviation still apply underneath, so nothing is lost.

Baseline deviation is deterministic and per-attribute (expected value + the share of sessions that held it); the model adds multivariate context on top with median-absolute-deviation attribution, chosen over a z-score because MAD is not distorted by the outliers being hunted.

### Phase 6 — Differentiators — *DNS correlation and CBOM complete; LLM remediation not started*
**Done:** DNS-correlated policy audit (MTA-STS / DANE / TLS-RPT / SPF / DMARC) and CycloneDX 1.6 CBOM export. → **14/14 scenarios passing**, every ground-truth finding category now implemented.

**DNS correlation** is the differentiator that costs one extra tshark pass. A real capture contains the lookups that preceded each SMTP connection, so we can answer what no single session can: *did the observed TLS behaviour comply with the policy the sender had already fetched?* A sender that retrieved `mode=enforce` and then delivered in cleartext is a provable violation, not an observation. Scenario 19 demonstrates it end to end.

Honesty rule enforced throughout: **no DNS in the capture means "cannot assess", never "not published"** — those are different claims and only one is supported by the evidence. The dashboard says so explicitly.

**CBOM** exports the observed cryptography as CycloneDX 1.6 `cryptographic-asset` components — the standard normally used for software supply-chain inventory, here produced from *negotiated traffic* rather than from source or configuration. Hybrid PQC groups are labelled with the FIPS 203 primitive they contain; classical groups are labelled as migration candidates. Framed as a migration inventory, never as a threat assessment.

**Not started:** LLM-generated vendor-specific remediation (detect Postfix from the banner → emit that exact `main.cf` diff). Needs an API key, so it is untestable in this environment. The per-category recommendations in `policy.json` already carry real config directives and verification commands.

### Phase 6b — PCAP slicing & reports — *complete*
Per-finding and per-session PCAP extraction, plus JSON and print-ready HTML reports.

**Slices are cut with the same display filter shown in the UI.** If the filter and the slice could disagree, "verify this yourself" would be hollow — so it is one string, used once. Each download carries `X-Evidence-Sha256`, `X-Parent-Sha256`, `X-Frame-Count` and `X-Display-Filter`, so the chain of custody survives the export. Verified: the F-0001 slice is 45 valid PCAP-NG frames containing the mangled `250-XXXXXXXA`, with a parent hash matching the capture.

**On PDF:** the HTML report carries `@page` rules and print styles, so "Save as PDF" in any browser produces the formal document. That deliberately avoids WeasyPrint, which pulls cairo, pango and gdk-pixbuf — roughly 100 MB of system libraries — to render a template we already have. If server-side PDF is ever required, WeasyPrint consumes this same HTML unchanged.

Report sections: evidence manifest · posture with per-dimension coverage · summary · findings with full evidence chains · DNS policy · PQC readiness · sessions · scope and limitations.

### Tier-2 — real X.509 certificates — *complete*
Eight **real certificates** — generated by the same library a CA uses, committed as DER fixtures in `testbed/certs/` — carried in TLS 1.2 handshakes. Full X.509 analysis: subject, issuer, SAN, serial, validity, key algorithm and size, signature algorithm, chain depth, SHA-256 fingerprint. → **15/15 scenarios passing**, 8 new finding categories.

Two correctness rules this phase exists to enforce:

- **Validity is evaluated at capture time, not at `now`.** A certificate that expired after the traffic was recorded was not a problem when the traffic happened. This is not theoretical: the `expiring_soon` fixture (notAfter 2026-03-05) is wall-clock expired today, and is correctly reported as *expiring soon* rather than *expired*, because the capture is dated 2026-03-02. Comparing against the wall clock would raise a false CRITICAL on every archived capture.
- **Chain trust stays UNKNOWN.** A capture rarely contains the relying party's trust store, so any trust verdict would be unfounded. We report what the presented chain contains and refuse to judge it.

TLS 1.2 is used deliberately in these scenarios — under TLS 1.3 the Certificate message is encrypted and there would be nothing to analyse, which is itself the point the Evidence Coverage Score makes.

Two obstacles worth recording: modern `cryptography` refuses to *sign* with SHA-1 (correctly), so the SHA-1 fixture is signed with SHA-256 and has its signature-algorithm OID rewritten — both OIDs DER-encode to the same length, and the signature does not verify, which is irrelevant because passive analysis parses the algorithm field and can never verify a signature anyway.

**Still synthetic:** the handshake *framing* around these real certificates. Docker-hosted Postfix/Dovecot with genuine handshakes would validate the parser against real-world traffic; the certificate analysis itself is fully exercised without it.

### Tier-2 Docker testbed — real handshakes — *complete*
Eight scenarios run real `aiosmtpd` servers with real OpenSSL TLS, captured by `tcpdump`. **All 8 analyse correctly**, every expected finding category detected on traffic nobody synthesised.

```bash
docker compose --profile testbed run --rm testbed   # → testbed/output/t2-*.pcap
```

**Architecture: one container, capture on loopback.** Server, client and tcpdump share a single network namespace, which removes the entire class of multi-container networking problems — no bridge, no inter-service DNS, nothing to mis-wire.

Two bugs this tier caught that tier 1 structurally could not:

- **No SNI in the handshake.** The client connected to `127.0.0.1`, and RFC 6066 forbids an IP literal in SNI, so OpenSSL omitted the extension entirely — and certificate hostname verification had nothing to check against. Our analyser correctly declined to judge rather than guessing, but the capture was unrealistic: real MTAs resolve and connect by name. Fixed by adding the testbed hostname to `/etc/hosts` and connecting by name. `certificate_hostname_mismatch` now fires.
- **Implicit TLS on an unregistered port is undetectable.** With no plaintext dialogue there is no greeting to identify, so the port is the only signal that a TLS stream is mail. Moved to 465. This is a real and permanent limitation, not a bug: implicit TLS on a non-standard port cannot be attributed to email from passive observation alone.

One behaviour that looked wrong and is not: every live capture yields **two** sessions. `aiosmtpd`'s controller opens a readiness probe connection before the client connects. Both are genuine TCP connections and both are correctly reconstructed.

`@SECLEVEL=0` is required for the 1024-bit key scenario — modern OpenSSL refuses to serve it otherwise. Same class of obstacle as `cryptography` refusing to sign with SHA-1: current crypto libraries actively resist producing bad artefacts, which makes testing detection of bad artefacts harder than it sounds.

### Remaining
- LLM remediation with RFC-grounded RAG (blocked: needs an API key)
- What-if remediation simulator
- OCSF export

### Phase 7 — Hardening & pitch (week 8+)
Performance on a 500k-packet capture, fuzz the parsers with public PCAPs, seed data for offline demo, rehearsed script, fallback recorded video.

---

## 13. Demo script

1. Upload `enterprise_email.pcapng` → manifest: SHA-256, 482,193 packets, time range.
2. Pipeline runs live → `1,842 TCP flows · 124 email sessions`.
3. Protocol breakdown: `SMTP 72 · IMAP 41 · POP3 11`.
4. Encryption: `TLS protected 111 · via STARTTLS 89 · implicit TLS 22 · plaintext 13 · incomplete 11`.
5. Posture: `74/100` — expand the six dimensions **with coverage percentages**. Say out loud: *"certificate coverage is 31% because 58 sessions used TLS 1.3, where the certificate is encrypted. We report what we can prove."* ← this line wins technical judges.
6. Findings: `CRITICAL 2 · HIGH 4 · MEDIUM 11 · LOW 7`.
7. Open **CRITICAL — SMTP AUTH credentials in cleartext**. Show redacted username, hash prefix, "credential not stored".
8. Open **CRITICAL — STARTTLS capability stripping**. Show the cross-session capability table: same server advertises STARTTLS in 82 sessions, mangled in 2. Show the encryption timeline. Show the mangled EHLO bytes.
9. Click **Verify in Wireshark** → copy display filter, download the sliced mini-PCAP, open it, point at the exact frame. *This is the moment that sells the project.*
10. Show the **server crypto profile** and the ML deviation with per-feature attribution and 91% anomaly confidence — and say explicitly: *"this is deviating behaviour, not a confirmed attack."*
11. Show **DNS correlation**: `corp.local publishes MTA-STS mode=enforce; sender fetched it; 13 sessions sent cleartext → policy violation`.
12. Show **PQC readiness + download CBOM** (CycloneDX 1.6 JSON).
13. Show **LLM remediation**: the actual Postfix `main.cf` diff with NIST citation and a verification command.
14. Run the **what-if simulator**: apply the three fixes → posture `74 → 91`. Stress it's a policy projection, not a claim the server changed.
15. Export JSON + PDF + OCSF.

---

## 14. Security & privacy

- **Never store or display message bodies.** Metadata, protocol state, TLS parameters, certificates, frame references only.
- **Credentials:** detect, redact, hash-prefix, never persist. (§4.6)
- Run Zeek/TShark **in a container, as a non-root user, with no network access**, on a read-only mount. Parsers are the attack surface.
- No shell string interpolation of filenames — `subprocess` with argument lists, always. Sanitise and re-generate filenames on upload.
- Enforce upload size limits and analysis timeouts.
- Preserve the capture SHA-256 in every export; chain of custody is a feature.
- Audit-log every analyst action.
- RBAC only if time permits — it is not a differentiator. (§15)

---

## 15. What we will NOT build

Say no to these firmly and repeatedly. Every hour here is an hour stolen from §4.

| ❌ | Why |
|---|---|
| Our own TCP reassembler | Zeek/TShark do it correctly, we won't |
| Our own TLS or X.509 parser | Ditto |
| Any cryptographic primitive (AES/RSA/ECDHE) | `cryptography` exists |
| TLS decryption / MITM | Out of scope, and we're a *passive* tool |
| An email client or full mail stack | Testbed only needs enough protocol to be real |
| A full SIEM | We *export to* SIEMs (OCSF); we don't build one |
| Active mail-server vulnerability scanning | The PS explicitly asks for passive analysis |
| Deep learning "so we can say AI" | Isolation Forest + explainability beats an unexplainable NN |
| Email content classification / DLP | Privacy violation and off-brief |
| Live capture from a NIC | Demo risk with no marginal credit; PCAP upload only |
| Kubernetes / microservices / message-bus architecture | Compose is enough; complexity is not a score |
| Multi-tenant RBAC, SSO, billing | Zero differentiation for a hackathon |
| Custom charting library | Recharts |
| Mobile app | No |
| Blockchain evidence ledger | The theme name is not a requirement. SHA-256 chain of custody is the real answer. Resist this. |

---

## 16. Honest limitations (state these openly — it's a strength)

1. TLS 1.3 encrypts the certificate; certificate analysis needs TLS ≤ 1.2 or a keylog.
2. Application data stays encrypted. We analyse handshakes, certificates, crypto metadata, and flow behaviour — not mail content. That is by design.
3. Certificate chain trust cannot be fully validated without the enterprise trust store → `UNKNOWN`, never a false `FAIL`.
4. Captures may be partial or truncated → `UNKNOWN` is a valid, first-class verdict.
5. An ML anomaly is deviating behaviour, not a confirmed attack.
6. The posture score is *our* methodology, anchored to published standards, with transparent configurable weights. It is not an industry-certified rating.
7. ECH hides SNI where deployed.

---

## 17. Standards & references

RFC 3207 (SMTP STARTTLS) · RFC 2595 / RFC 7817 (IMAP/POP3 TLS) · RFC 8314 (implicit TLS for submission/access) · RFC 8446 (TLS 1.3) · RFC 8996 (TLS 1.0/1.1 deprecation) · RFC 8461 (MTA-STS) · RFC 8460 (TLS-RPT) · RFC 7672 (DANE for SMTP) · RFC 6698 (DANE/TLSA) · NIST SP 800-52 Rev. 2 · NIST SP 800-177 Rev. 1 · FIPS 203 (ML-KEM) / FIPS 204 (ML-DSA) · CNSA 2.0 · CA/Browser Forum Baseline Requirements · Mozilla Server Side TLS · CycloneDX 1.6 CBOM · OCSF · JA3/JA3S · JA4/JA4S

---

## 18. Quick start

Generate the labelled corpus — needs nothing but Python 3.9+:

```bash
python3 -m testbed.synthetic.generate --all
# → testbed/output/<scenario>.pcap + <scenario>.truth.json
```

Run the platform:

```bash
cp .env.example .env
make up                                   # postgres + api (tshark)
make health                               # verify the tool inventory
make test-upload PCAP=testbed/output/13-enterprise-mixed.pcap
```

| Service | URL |
|---|---|
| API docs | http://localhost:8000/docs |
| Postgres | `localhost:5433` (5433 to avoid colliding with a local install) |

---

## 19. Team split (suggested)

| Track | Owns |
|---|---|
| **Pipeline** | Zeek/TShark runners, flow indexing, TCP→session, IMAP/POP3 parsers, state machine |
| **Crypto** | TLS handshake analysis, X.509, fingerprints, policy engine, PQC/CBOM |
| **Intelligence** | Features, Isolation Forest, server profiles, posture scoring, LLM remediation |
| **Product** | React dashboard, timeline, evidence viewer, reports (HTML/PDF/JSON/OCSF) |
| **Testbed** | Scenario servers, cert generation, capture automation, labelled corpus, CI fixtures |

Phase 3 is the hard dependency — the Crypto and Pipeline tracks must land it before Intelligence has anything real to model.
