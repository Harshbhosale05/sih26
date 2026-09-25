# Testbed — where the PCAPs come from

We generate our own captures. This is not a workaround for lacking real data; it
is a requirement. Our ML needs labels, and no public capture exists that is
tagged "STARTTLS capability stripped by an on-path proxy". Without ground truth
we cannot prove a detector works or train anything on it.

Two tiers, chosen per scenario by what the scenario actually needs.

---

## Tier 1 — Synthetic (`testbed/synthetic/`)

Pure Python. We write the packet bytes ourselves: Ethernet, IPv4, TCP with
correct checksums and sequence tracking, then real wire-format TLS
ClientHello/ServerHello messages.

**No Docker. No root. No network. Runs in CI.**

```bash
python3 -m testbed.synthetic.generate --list     # show scenarios
python3 -m testbed.synthetic.generate --all      # generate everything
python3 -m testbed.synthetic.generate 09-starttls-stripping
```

Output lands in `testbed/output/`:

| File | Contents |
|---|---|
| `<scenario>.pcap` | the capture |
| `<scenario>.truth.json` | ground truth: sessions, expected findings, **exact evidence frame numbers**, and the pcap's sha256 |

### Why synthetic is *better* here, not merely easier

For the plaintext phase of email protocols — which carries our highest-value
findings — hand-building the bytes beats capturing them:

- **Ground truth is exact.** The truth file says frame 182 carries the mangled
  capability line. Tests assert on that number. A detector that fires on the
  right session for the wrong reason still fails.
- **Deterministic.** Same scenario, byte-identical file, every run. A changed
  sha256 means the generator changed, not the capture.
- **No privacy or legal surface.** Nothing was ever captured from a real network.

### What tier 1 covers

Protocol state machines (SMTP/IMAP/POP3), STARTTLS *and* POP3's `STLS`,
capability stripping, downgrade-and-fallback, cleartext credentials, implicit
TLS, negotiated TLS version and cipher suite, supported groups, SNI,
hybrid-PQC group offers (`X25519MLKEM768`, 0x11EC), segmented commands, and
truncated captures.

### What tier 1 cannot cover

Real certificates and real key exchange. The handshakes are structurally valid
and fully dissectable, but there is no functioning crypto and no Certificate
message. Anything touching X.509 needs tier 2.

### Current scenarios

| Scenario | Label | What it proves |
|---|---|---|
| `01-secure-tls13` | `secure` | **Negative control.** Any finding above INFO is a false positive |
| `03-deprecated-tls` | `deprecated_tls` | TLS 1.0 negotiated (RFC 8996) |
| `07-no-forward-secrecy` | `no_pfs` | Static RSA key exchange |
| `08-starttls-not-enforced` | `starttls_not_enforced` | Advertised, never requested |
| `09-starttls-stripping` | `starttls_stripping` | **Headline.** 6 sessions advertise STARTTLS, 2 carry a length-preserving mangled token |
| `10-downgrade-fallback` | `downgrade_fallback` | Requested → refused → cleartext anyway |
| `11-credential-exposure` | `credential_exposure` | Cleartext creds on all three protocols |
| `12-implicit-tls` | `secure_implicit` | 465/993/995, no plaintext phase (RFC 8314) |
| `13-enterprise-mixed` | `enterprise_normal` | **Demo capture.** 37 sessions, 2 servers, realistic problem tail |
| `15-pqc-readiness` | `pqc_ready` | Clients offer hybrid PQC, server never selects it |
| `16-incomplete-evidence` | `incomplete_evidence` | Truncated mid-session → must report UNKNOWN |
| `17-segmented-starttls` | `secure` | STARTTLS split across segments — catches packet-oriented parsers |

Two of these exist purely to catch *our own* false positives (`01`, `17`) and
one to catch our worst failure mode — a confident verdict on absent evidence
(`16`). Build them early; they are cheap and they keep us honest.

### Verifying a generated capture

```bash
tcpdump -r testbed/output/09-starttls-stripping.pcap -nn -A | head -40
tcpdump -r testbed/output/13-enterprise-mixed.pcap -vv -nn | grep -c "bad cksum"   # → 0
```

---

## Tier 2 — Docker testbed (`testbed/servers/`) — *not yet built*

Real mail servers, real TLS, real certificates, captured with `tcpdump`.

```
        Docker network "labnet"
   ┌──────────────────────────┐
   │ mail server (per-scenario│
   │ TLS config + cert)       │
   └───────────┬──────────────┘
               │  ← tcpdump sidecar sharing the
               │     server's network namespace
   ┌───────────▼──────────────┐
   │ client / mail generator  │
   └──────────────────────────┘
               ↓
        scenario-NN.pcap  +  SSLKEYLOGFILE
```

### Design decisions, already made

**Use `aiosmtpd` with a per-scenario `ssl.SSLContext`, not Postfix, for most
scenarios.** Forcing Postfix to negotiate TLS 1.0 with a specific weak cipher is
hours of config archaeology; with `aiosmtpd` it is three lines
(`ctx.minimum_version`, `ctx.maximum_version`, `ctx.set_ciphers`). Run *one*
real Postfix + Dovecot scenario for realism, not ten.

**Capture with `SSLKEYLOGFILE` exported.** TLS 1.3 encrypts the Certificate
message, so without keys there is nothing to analyse. The keylog lets us demo
full certificate analysis on TLS 1.3 and clearly label those sessions as
keylog-assisted.

**Expect a fight with OpenSSL over TLS 1.0/1.1.** Modern OpenSSL refuses them
even server-side. Needs `@SECLEVEL=0`, `MinProtocol=TLSv1`, and probably an
older OpenSSL base image. Budget a day; it always takes longer than expected.

### Certificates tier 2 must generate

valid · expired · not-yet-valid · wrong CN/SAN · 1024-bit RSA · SHA-1 signed ·
self-signed · incomplete chain

Generated with the `cryptography` library against the fixed scenario epoch
(`BASE_TIME` = 2026-03-02 09:15:00 UTC) so expiry logic is reproducible.

---

## Tier 3 — Public captures (not generated)

Wireshark SampleCaptures, malware-traffic-analysis.net. Unlabelled and messy.
Their job is robustness: our parsers must not crash on real-world garbage. Never
used for training or for accuracy claims.
