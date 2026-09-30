"""Formal assessment report (HTML, and the source of the PDF export).

Laid out as a conventional forensic / security assessment report: cover page
with document control, table of contents, numbered sections, a findings
register, detailed findings, remediation plan and appendices. Layout uses
tables and block flow only, so browsers and WeasyPrint render it identically;
`@page` rules supply running headers, footers and page numbers in the PDF.

Everything is inlined: no external CSS, fonts or scripts. The report has to
survive being emailed around and opened offline.
"""

from __future__ import annotations

from datetime import datetime
from html import escape

SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]

# Muted, print-safe severity colours, used only for the severity cell.
_SEV = {
    "CRITICAL": ("#7f1d1d", "#fbe9e9"),
    "HIGH": ("#9a3412", "#fdefe6"),
    "MEDIUM": ("#854d0e", "#fdf6e3"),
    "LOW": ("#1e3a8a", "#eaf0fb"),
    "INFO": ("#374151", "#f1f2f4"),
}

_SEVERITY_DEFINITIONS = [
    ("CRITICAL", "Confidentiality of credentials or message content is lost now, or an active "
                 "downgrade was observed. Remediate immediately."),
    ("HIGH", "A weakness that directly enables interception or impersonation, such as a "
             "deprecated protocol, no forward secrecy, or an invalid certificate."),
    ("MEDIUM", "A weakness that reduces security margin or depends on client behaviour, such as "
               "legacy cipher modes or an unused STARTTLS offer."),
    ("LOW", "A deviation from current best practice with limited direct exposure."),
    ("INFO", "An observation or a limit of the evidence. No action required on the server."),
]

_STANDARDS = [
    ("NIST SP 800-52 Rev. 2", "Guidelines for the Selection, Configuration and Use of TLS Implementations"),
    ("NIST SP 800-177 Rev. 1", "Trustworthy Email"),
    ("RFC 8996", "Deprecating TLS 1.0 and TLS 1.1"),
    ("RFC 8446", "The Transport Layer Security (TLS) Protocol Version 1.3"),
    ("RFC 3207 / RFC 8314", "SMTP STARTTLS; Cleartext Considered Obsolete for Email Submission and Access"),
    ("RFC 8461 / RFC 7672 / RFC 8460", "MTA-STS; DANE for SMTP; SMTP TLS Reporting"),
    ("RFC 5280", "Internet X.509 PKI Certificate and CRL Profile"),
    ("CA/Browser Forum", "Baseline Requirements for Publicly-Trusted TLS Certificates"),
    ("FIPS 203", "Module-Lattice-Based Key-Encapsulation Mechanism (ML-KEM)"),
]

_GLOSSARY = [
    ("AEAD", "Authenticated Encryption with Associated Data (e.g. AES-GCM, ChaCha20-Poly1305)."),
    ("CBOM", "Cryptographic Bill of Materials (CycloneDX) listing observed algorithms and certificates."),
    ("DANE / TLSA", "DNS-based Authentication of Named Entities; pins the server key in DNSSEC-signed DNS."),
    ("Forward secrecy", "Property of ephemeral key exchange (ECDHE/DHE): a later key compromise does not expose past sessions."),
    ("HNDL", "Harvest-now, decrypt-later: recording traffic today to decrypt it with future capability."),
    ("Implicit TLS", "TLS from the first byte on a dedicated port (465, 993, 995); no plaintext phase."),
    ("JA3 / JA4", "Standard TLS client and server fingerprints derived from handshake parameters."),
    ("MTA-STS", "Mail Transfer Agent Strict Transport Security (RFC 8461); requires TLS for delivery to a domain."),
    ("STARTTLS / STLS", "Command upgrading a plaintext SMTP/IMAP (STARTTLS) or POP3 (STLS) session to TLS."),
    ("STARTTLS stripping", "On-path removal or alteration of the STARTTLS capability to force cleartext."),
]


def _e(value) -> str:
    return escape(str(value if value is not None else "—"))


def _d(iso: str | None) -> str:
    if not iso:
        return "—"
    try:
        return datetime.fromisoformat(iso.replace("Z", "+00:00")).strftime("%d %b %Y %H:%M:%S UTC")
    except ValueError:
        return iso


def _sev(severity: str) -> str:
    ink, bg = _SEV.get(severity, _SEV["INFO"])
    return f'<td class="sev" style="color:{ink};background:{bg}">{_e(severity.title())}</td>'


def _rating(score: int | None, critical: int) -> str:
    if score is None:
        return "Not assessable"
    if critical:
        return "Poor"
    return "Strong" if score >= 80 else "Moderate" if score >= 60 else "Weak" if score >= 40 else "Poor"


_STATE_LABELS = {
    "TLS_ESTABLISHED": "TLS (STARTTLS)", "IMPLICIT_TLS": "TLS (implicit)",
    "STARTTLS_ADVERTISED_NOT_USED": "Cleartext; STARTTLS offered, not used",
    "STARTTLS_NOT_ADVERTISED": "Cleartext; STARTTLS not offered",
    "STARTTLS_REJECTED": "Upgrade refused", "STARTTLS_NEGOTIATION_FAILED": "TLS negotiation failed",
    "PLAINTEXT_AFTER_FAILURE": "Cleartext after failed upgrade", "PLAINTEXT_THROUGHOUT": "Cleartext",
    "TRUNCATED": "Undetermined (truncated)", "UNKNOWN": "Undetermined",
}

_ACRONYMS = {"tls": "TLS", "starttls": "STARTTLS", "pqc": "PQC", "mta": "MTA", "sts": "STS", "dmarc": "DMARC",
              "dane": "DANE", "tlsrpt": "TLS-RPT", "dns": "DNS"}


def _category(category: str) -> str:
    words = [_ACRONYMS.get(w, w) for w in category.split("_")]
    text = " ".join(words).replace("MTA STS", "MTA-STS")
    return text[0].upper() + text[1:]


def _pct(n, d) -> str:
    return f"{100 * n / d:.1f}%" if d else "—"


def _h(level: int, anchor: str, number: str, title: str) -> str:
    return f'<h{level} id="{anchor}"><span class="n">{number}</span>{_e(title)}</h{level}>'


def _mono(value) -> str:
    return f'<span class="mono">{_e(value)}</span>'


def _table(head: list[str], rows: list[list[str]], widths: list[str] | None = None, cls: str = "") -> str:
    cols = "".join(f'<col style="width:{w}">' for w in widths) if widths else ""
    th = "".join(f"<th>{h}</th>" for h in head)
    body = "".join(
        "<tr>" + "".join(c if c.startswith("<td") else f"<td>{c}</td>" for c in r) + "</tr>" for r in rows
    )
    if not rows:
        body = f'<tr><td colspan="{len(head)}" class="muted">None.</td></tr>'
    return (
        f'<table class="t {cls}"><colgroup>{cols}</colgroup>'
        f"<thead><tr>{th}</tr></thead><tbody>{body}</tbody></table>"
    )


def render(report: dict) -> str:
    meta, ev, po, su, cv = (
        report["report"], report["evidence"], report["posture"], report["summary"], report["coverage"],
    )
    findings = report["findings"]
    fails = [f for f in findings if f["verdict"] == "FAIL" and f["severity"] != "INFO"]
    notes = [f for f in findings if f not in fails]
    sev_counts = {s: sum(1 for f in fails if f["severity"] == s) for s in SEVERITY_ORDER}
    critical = sev_counts["CRITICAL"]
    stats = report.get("tls_stats") or {}
    email_sessions = [s for s in report["sessions"] if s.get("protocol")]
    protected = sum(1 for s in email_sessions if s["encryption_state"] in ("TLS_ESTABLISHED", "IMPLICIT_TLS"))
    creds = sum(1 for f in fails if f["category"] == "cleartext_credential_exposure")
    rating = _rating(po["overall"], critical)
    rem = report.get("remediation") or {}
    steps = rem.get("steps") or []
    prios = {p["ref"]: p for p in report.get("priorities") or []}
    report_id = meta.get("report_id", ev["capture_ref"])
    classification = (meta.get("classification") or "CONFIDENTIAL").split("—")[0].strip()
    def cap(text: str) -> str:
        return f'<p class="cap">{_e(text)}</p>'

    def asset(f: dict) -> str:
        ev_ = f.get("evidence") or {}
        profile = ev_.get("server_profile") if isinstance(ev_.get("server_profile"), dict) else {}
        return ev_.get("server") or profile.get("server") or f.get("session_ref") or "Environment"

    # ------------------------------------------------------------------ cover
    cover = f"""
    <section class="cover">
      <div class="org">SecureMailScope · Email Cryptographic Assessment</div>
      <div class="cover-title">{_e(meta['title'])}</div>
      <div class="cover-sub">Passive analysis of captured SMTP, IMAP and POP3 traffic</div>
      <table class="kv">
        <tr><th>Report reference</th><td>{_e(report_id)}</td></tr>
        <tr><th>Evidence item</th><td>{_e(ev['capture_ref'])} — {_e(ev['filename'])}</td></tr>
        <tr><th>Evidence SHA-256</th><td class="mono">{_e(ev['sha256'])}</td></tr>
        <tr><th>Traffic period</th><td>{_d(ev['first_packet_at'])} to {_d(ev['last_packet_at'])}</td></tr>
        <tr><th>Report date</th><td>{_d(meta['generated_at'])}</td></tr>
        <tr><th>Classification</th><td>{_e(meta.get('classification'))}</td></tr>
      </table>
      <div class="doc-control">
        <div class="dc-title">Document control</div>
        {_table(["Version", "Date", "Author", "Description"],
                [[_e(meta.get('version', '1.0')), _d(meta['generated_at'])[:11], "SecureMailScope (automated)",
                  "Initial assessment report"]],
                ["12%", "20%", "30%", "38%"])}
        <div class="dc-title" style="margin-top:8pt">Review and approval</div>
        {_table(["Role", "Name", "Signature", "Date"],
                [["Prepared by", "SecureMailScope automated analysis", "", ""],
                 ["Reviewed by", "", "", ""], ["Approved by", "", "", ""]],
                ["20%", "38%", "24%", "18%"], "sign")}
      </div>
      <div class="cover-foot">This document contains information derived from network evidence and is intended
      for the named recipients only. Handle in accordance with its classification.</div>
    </section>"""

    # ------------------------------------------------------------------ contents
    toc_items = [
        ("s1", "1", "Executive Summary"), ("s2", "2", "Scope and Methodology"),
        ("s3", "3", "Evidence Details"), ("s4", "4", "Summary of Findings"),
        ("s5", "5", "Detailed Findings"), ("s6", "6", "Cryptographic Posture Assessment"),
        ("s7", "7", "Risk Analysis and Prioritisation"), ("s8", "8", "Remediation Plan"),
        ("sa", "A", "Appendix A — Session Inventory"), ("sb", "B", "Appendix B — Scoring Methodology"),
        ("sc", "C", "Appendix C — Glossary"),
    ]
    toc = '<section class="toc"><h1>Contents</h1><ul>' + "".join(
        f'<li><a href="#{a}"><span class="tn">{n}</span>{_e(t)}</a></li>' for a, n, t in toc_items
    ) + "</ul></section>"

    # ------------------------------------------------------------------ 1 executive summary
    protos = ", ".join(f"{v} {k}" for k, v in su["by_protocol"].items()) or "none"
    issues_list = "".join(
        f"<li><b>{_e(f['title'])}</b> — {_e(f['severity'].title())}, {_mono(asset(f))} ({_e(f['ref'])}).</li>"
        for f in fails[:6]
    ) or "<li>No findings requiring action were identified.</li>"
    actions = "".join(
        f"<li>{_e(st['title'])} ({_e(', '.join(st['servers']) or 'all servers')}).</li>" for st in steps[:5]
    ) or "<li>No configuration changes are required.</li>"
    summary_rows = [
        ["Overall rating", f"<b>{_e(rating)}</b>" + (" (critical findings present)" if critical else "")],
        ["Posture score", f"{_e(po['overall'])} / 100 ({po['dimensions_assessed']} of {po['dimensions_total']} dimensions assessed)"],
        ["Findings requiring action", " · ".join(f"{sev_counts[s]} {s.title()}" for s in SEVERITY_ORDER[:4])],
        ["Sessions encrypted", f"{protected} of {len(email_sessions)} ({_pct(protected, len(email_sessions))})"],
        ["Credential exposures", f"{creds} finding(s) of credentials transmitted in cleartext"],
    ]
    if rem.get("target"):
        summary_rows.append(
            ["Projected score after remediation", f"{_e(rem['target']['score'])} / 100 after {len(steps)} change(s)"]
        )
    exec_summary = f"""
      {_h(1, 's1', '1', 'Executive Summary')}
      {_h(2, 's1-1', '1.1', 'Overview')}
      <p>This report presents the results of a passive cryptographic security assessment of the email traffic
      contained in evidence item {_e(ev['capture_ref'])} ({_e(ev['filename'])}). The evidence holds
      {_e(ev['packet_count'])} packets recorded between {_d(ev['first_packet_at'])} and {_d(ev['last_packet_at'])}.
      A total of {len(email_sessions)} email sessions ({_e(protos)}) between {_e(stats.get('clients'))} client(s)
      and {_e(stats.get('servers'))} server endpoint(s) were reconstructed and assessed. No system was contacted
      or scanned during the assessment.</p>
      <p>The overall cryptographic posture is rated <b>{_e(rating)}</b>{' because critical findings are present' if critical else ''};
      the weighted posture score is {_e(po['overall'])} out of 100. The assessment identified {len(fails)} finding(s) requiring action: {sev_counts['CRITICAL']} critical,
      {sev_counts['HIGH']} high, {sev_counts['MEDIUM']} medium and {sev_counts['LOW']} low.
      {f'A further {len(notes)} observation(s) record limits of the available evidence.' if notes else ''}</p>
      {_table(["Measure", "Result"], summary_rows, ["38%", "62%"], "kv2")}
      {cap('Assessment summary')}
      {_h(2, 's1-2', '1.2', 'Principal Findings')}
      <p>The most significant findings, in order of priority, are listed below and described in Section 5.</p>
      <ol class="plain">{issues_list}</ol>
      {_h(2, 's1-3', '1.3', 'Principal Recommendations')}
      <p>The following changes are recommended, in order. Section 8 gives the configuration for the server software
      identified in the traffic and the commands required to verify each change.</p>
      <ol class="plain">{actions}</ol>"""

    # ------------------------------------------------------------------ 2 methodology
    method = f"""
      {_h(1, 's2', '2', 'Scope and Methodology')}
      {_h(2, 's2-1', '2.1', 'Scope')}
      <p>The assessment covers every SMTP, IMAP and POP3 session present in the evidence item, identified by port
      and by protocol signature so that services on non-standard ports are included. Its objective is to determine
      the cryptographic protection actually negotiated by the mail infrastructure: use of TLS and STARTTLS,
      protocol versions, cipher suites, key exchange, certificates and supporting DNS policy.</p>
      {_h(2, 's2-2', '2.2', 'Approach')}
      <ol class="plain">
        <li>Evidence verification: SHA-256 digest computed on receipt; container and capture metadata validated.</li>
        <li>Flow indexing and TCP stream reassembly, retaining the source frame of every byte.</li>
        <li>Email session reconstruction and encryption-state analysis (STARTTLS/STLS negotiation, implicit TLS,
        refusals, fallbacks and capability tampering).</li>
        <li>TLS handshake analysis: negotiated version, cipher suite, key exchange group, forward secrecy,
        JA3/JA4 fingerprints and post-quantum key exchange.</li>
        <li>X.509 analysis of certificates visible in TLS 1.2 and earlier: validity at capture time, key strength,
        signature algorithm, hostname coverage, chain signature verification and trust anchoring.</li>
        <li>Rule-based detection against the standards listed below. Every finding cites the frames that support it.</li>
        <li>Session risk classification, remediation prioritisation and posture scoring (Section 7, Appendix B).</li>
      </ol>
      {_h(2, 's2-3', '2.3', 'Standards Referenced')}
      {_table(["Reference", "Title"], [[_e(a), _e(b)] for a, b in _STANDARDS], ["30%", "70%"])}
      {cap('Standards referenced')}
      {_h(2, 's2-4', '2.4', 'Severity Definitions')}
      {_table(["Severity", "Definition"], [[_sev(s), _e(d)] for s, d in _SEVERITY_DEFINITIONS], ["16%", "84%"])}
      {cap('Severity definitions')}
      {_h(2, 's2-5', '2.5', 'Limitations')}
      <ul class="plain">{''.join(f'<li>{_e(x)}</li>' for x in report['limitations'])}</ul>"""

    # ------------------------------------------------------------------ 3 evidence
    duration = f"{ev['duration_seconds']:.3f} s" if ev.get("duration_seconds") is not None else "—"
    snaplen = _e(ev["snaplen"]) + (" (truncated; payload analysis may be incomplete)" if ev["snaplen_truncated"] else "")
    evidence = f"""
      {_h(1, 's3', '3', 'Evidence Details')}
      {_h(2, 's3-1', '3.1', 'Evidence Item')}
      {_table(["Attribute", "Value"], [
          ["Reference", _e(ev['capture_ref'])], ["File name", _e(ev['filename'])],
          ["Format", _e(ev['format'])], ["Size", f"{_e(ev['size_bytes'])} bytes"],
          ["Packets", _e(ev['packet_count'])], ["First packet", _d(ev['first_packet_at'])],
          ["Last packet", _d(ev['last_packet_at'])], ["Duration", duration],
          ["Snapshot length", snaplen], ["SHA-256", _mono(ev['sha256'])],
      ], ["30%", "70%"], "kv2")}
      {cap('Evidence item')}
      {_h(2, 's3-2', '3.2', 'Integrity and Chain of Custody')}
      <p>The SHA-256 digest above was computed when the evidence item was received and is recorded against every
      finding in this report. Analysis was performed on the stored item without modification. Extracts supplied
      for verification (per-session and per-finding capture slices) carry their own SHA-256 digest together with
      the digest of this parent item.</p>
      {_table(["Date / time (UTC)", "Action", "Performed by"], [
          [_d(ev.get('uploaded_at')), "Evidence received; SHA-256 computed; metadata extracted", "SecureMailScope"],
          [_d(meta['generated_at']), "Analysis performed; report generated", "SecureMailScope"],
      ], ["30%", "48%", "22%"])}
      {cap('Chain of custody')}"""

    # ------------------------------------------------------------------ 4 summary of findings
    sev_rows = [[_sev(s), str(sev_counts[s])] for s in SEVERITY_ORDER[:4]] + [["<b>Total</b>", f"<b>{len(fails)}</b>"]]
    register_rows = [
        [_mono(f["ref"]), _e(f["title"]), _sev(f["severity"]), _mono(asset(f)),
         _e(prios[f["ref"]]["tier"]) if f["ref"] in prios else "—"]
        for f in fails
    ]
    findings_summary = f"""
      {_h(1, 's4', '4', 'Summary of Findings')}
      {_table(["Severity", "Count"], sev_rows, ["60%", "40%"], "narrow")}
      {cap('Findings by severity')}
      {_table(["ID", "Finding", "Severity", "Affected asset", "Priority"], register_rows,
              ["10%", "44%", "12%", "22%", "12%"])}
      {cap('Findings register')}"""

    # ------------------------------------------------------------------ 5 detailed findings
    def detail(i: int, f: dict) -> str:
        lines = []
        if f.get("session_ref"):
            lines.append(f"Session {_e(f['session_ref'])} ({f['affected_sessions']} session(s) affected)")
        if f.get("evidence_frames"):
            lines.append("Frames " + _e(", ".join(str(x) for x in f["evidence_frames"])))
        display_filter = (
            f'<p class="label">Wireshark display filter</p><div class="code">{_e(f["wireshark_filter"])}</div>'
            if f.get("wireshark_filter") else ""
        )
        prio = prios.get(f["ref"])
        prio_text = f"{prio['tier']} ({prio['tier_label']})" if prio else "—"
        return f"""
        <div class="finding">
          {_h(2, f"f-{f['ref']}", f"5.{i}", f"{f['ref']}: {f['title']}")}
          <table class="t meta">
            <colgroup><col style="width:17%"><col style="width:33%"><col style="width:17%"><col style="width:33%"></colgroup>
            <tr><th>Severity</th>{_sev(f['severity'])}<th>Priority</th><td>{_e(prio_text)}</td></tr>
            <tr><th>Category</th><td>{_e(_category(f['category']))}</td><th>Status</th><td>Open</td></tr>
            <tr><th>Affected asset</th><td>{_mono(asset(f))}</td>
                <th>Detection</th><td>{_e(f['detection_method'].capitalize())} rule; confidence {int(f['confidence'] * 100)}%</td></tr>
          </table>
          <h4>Description</h4><p>{_e(f['description'])}</p>
          <h4>Analysis</h4><p>{_e(f['rationale'])}</p>
          <h4>Evidence</h4><p>{'<br>'.join(lines) or 'Capture-level observation.'}</p>{display_filter}
          <h4>Recommendation</h4><p>{_e(f.get('recommendation') or 'See Section 8.')}</p>
          <h4>References</h4><p>{_e(', '.join(f.get('standards') or []) or '—')}</p>
        </div>"""

    observations = ""
    if notes:
        observations = f"""
      {_h(2, 's5-obs', f'5.{len(fails) + 1}', 'Observations')}
      <p>The following items record where the evidence could not support a conclusion. They reduce evidence
      coverage but are not faults of the systems assessed.</p>
      {_table(["ID", "Session", "Observation", "Verdict"],
              [[_mono(n["ref"]), _mono(n["session_ref"]), _e(n["title"]), _e(n["verdict"])] for n in notes],
              ["12%", "16%", "58%", "14%"], "small")}
      {cap('Observations')}"""
    detailed = f"""
      {_h(1, 's5', '5', 'Detailed Findings')}
      <p>Each finding states what was observed, the analysis supporting the conclusion, the location of the
      evidence in the capture and the recommended action. The display filters can be applied in Wireshark to the
      evidence item to verify each finding independently.</p>
      {''.join(detail(i, f) for i, f in enumerate(fails, start=1)) or '<p>No findings requiring action.</p>'}
      {observations}"""

    # ------------------------------------------------------------------ 6 posture
    dim_rows = [
        [f"<b>{_e(d['label'])}</b><br><span class='muted'>{_e(d['standard'])}</span>",
         "Not assessed" if d["score"] is None else f"<b>{d['score']}</b>",
         f"{int(d['weight'] * 100)}%",
         "—" if d["coverage_pct"] is None else f"{d['coverage_pct']:g}%",
         _e("; ".join(d.get("contributors") or []) or d["detail"])]
        for d in po["dimensions"]
    ]
    tls_total = stats.get("tls_sessions") or 0
    version_rows = [
        [_e(v), str(n), _pct(n, tls_total),
         "Deprecated (RFC 8996)" if v in ("TLS 1.0", "TLS 1.1", "SSL 3.0") else "Acceptable" if v == "TLS 1.2" else "Recommended"]
        for v, n in sorted((stats.get("by_version") or {}).items(), reverse=True)
    ]
    suite_rows = [
        [_mono(s["suite"]), _e(", ".join(s["versions"])), "Yes" if s["forward_secrecy"] else "No",
         "Yes" if s["aead"] else "No", str(s["sessions"])]
        for s in stats.get("suites") or []
    ]
    stls = report.get("starttls") or {}
    stls_rows = [
        [_e(f["label"]), str(f["count"]), "—" if f["pct_of_start"] is None else f"{f['pct_of_start']:g}%"]
        for f in stls.get("funnel") or []
    ]
    owners = {"server": "Server", "client": "Client", "network": "Network", "both": "Client and server"}
    outcome_rows = [
        [_e(f["label"]), _e(owners.get(f["owner"], "—")), str(f["count"]), _e(f["explanation"])]
        for f in stls.get("failure_points") or [] if f["count"]
    ]
    if stls_rows and (stls.get("summary") or {}).get("starttls_eligible"):
        stls_block = (
            _table(["Stage", "Sessions", "Of plaintext-start sessions"], stls_rows, ["50%", "20%", "30%"])
            + cap("STARTTLS upgrade stages")
        )
        if outcome_rows:
            stls_block += _table(["Outcome", "Remediation owner", "Sessions", "Explanation"], outcome_rows,
                                 ["24%", "16%", "10%", "50%"], "small") + cap("STARTTLS outcomes")
    else:
        stls_block = "<p>All sessions used implicit TLS; there is no STARTTLS negotiation to assess.</p>"

    certs = report.get("certificates") or []
    cert_rows = [
        [_mono(c["session"]), _e(c["subject"]), _e(c["issuer"]), f"{_e(c['key'])}<br>{_e(c['signature'])}",
         f"{_e(c['not_before'])}<br>{_e(c['not_after'])}", _e((c["chain_trust"] or "").replace("_", " ").lower()),
         _e(", ".join(c["issues"]) or "None")]
        for c in certs
    ]
    cert_block = (
        _table(["Session", "Subject", "Issuer", "Key / signature", "Validity", "Chain", "Issues"], cert_rows,
               ["10%", "16%", "15%", "18%", "13%", "12%", "16%"], "small") + cap("Certificate inventory")
        if certs else ""
    )
    pqc = report.get("pqc_readiness") or {}
    pqc_rows = [[_e(t["label"]), str(t["sessions"]), f"{t['pct']:g}%", _e(t["explanation"])] for t in pqc.get("exposure") or []]
    pqc_block = (
        _table(["Exposure tier", "Sessions", "Share", "Explanation"], pqc_rows, ["26%", "11%", "10%", "53%"], "small")
        + cap("Harvest-now, decrypt-later exposure")
        if pqc_rows else ""
    )
    dns = report.get("dns_policy")
    if dns and dns.get("observed"):
        def yn(v):
            return "Yes" if v else "No" if v is False else "—"
        dns_rows = [
            [_mono(d["domain"]), yn(d["mta_sts"]["published"]), yn(d["dane"]["published"]), yn(d["tls_rpt"]["published"]),
             _e(d["dmarc"]["policy"]) if d["dmarc"]["published"] else "No", _mono(", ".join(d["mx_hosts"]) or "—")]
            for d in dns["domains"]
        ]
        dns_block = _table(["Domain", "MTA-STS", "DANE", "TLS-RPT", "DMARC", "MX hosts"], dns_rows,
                           ["22%", "11%", "10%", "11%", "12%", "34%"], "small") + cap("Email security policy observed in DNS")
    else:
        dns_block = ("<p>The evidence contains no DNS traffic, so MTA-STS, DANE, TLS-RPT and DMARC policy could not "
                     "be assessed. This does not indicate that these policies are absent.</p>")

    posture = f"""
      {_h(1, 's6', '6', 'Cryptographic Posture Assessment')}
      {_h(2, 's6-1', '6.1', 'Posture Score')}
      <p>The posture score is {_e(po['overall'])} / 100 (rating: {_e(rating)}). {_e(po['note'])} The calculation is
      given in Appendix B.</p>
      {_table(["Dimension", "Score", "Weight", "Coverage", "Basis"], dim_rows, ["25%", "10%", "9%", "11%", "45%"], "small")}
      {cap('Posture score by dimension')}
      {_h(2, 's6-2', '6.2', 'Protocol Versions and Cipher Suites')}
      <p>{tls_total} of {_e(stats.get('email_sessions'))} email sessions negotiated TLS.</p>
      {_table(["Protocol version", "Sessions", "Share", "Status"], version_rows, ["30%", "18%", "18%", "34%"])}
      {cap('Negotiated TLS protocol versions')}
      {_table(["Cipher suite", "Version", "Forward secrecy", "AEAD", "Sessions"], suite_rows,
              ["48%", "14%", "14%", "10%", "14%"], "small")}
      {cap('Negotiated cipher suites')}
      {_h(2, 's6-3', '6.3', 'STARTTLS Negotiation')}
      {stls_block}
      {_h(2, 's6-4', '6.4', 'Certificates')}
      <p>Certificates are visible only in TLS 1.2 and earlier handshakes, because TLS 1.3 encrypts the certificate
      message. {cv['certificate_observable']} of {cv['tls_sessions']} TLS session(s) presented an observable
      certificate. Validity is evaluated at the time the traffic was captured.</p>
      {cert_block}
      {_h(2, 's6-5', '6.5', 'Post-Quantum Readiness')}
      <p>Readiness score {_e(pqc.get('score'))} / 100 ({_e(pqc.get('level_label') or 'not assessable')}).
      {_e(pqc.get('framing'))}</p>
      {pqc_block}
      {_h(2, 's6-6', '6.6', 'Email Security Policy (DNS)')}
      {dns_block}"""

    # ------------------------------------------------------------------ 7 risk analysis
    prio_rows = [
        [str(p["rank"]), _mono(p["ref"]), _e(p["title"]), _sev(p["severity"]), f"{p['priority']:.0f}", _e(p["tier"]),
         _e("; ".join(f"{x['factor']} {x['points']:g}" for x in p["factors"] if x["points"]))]
        for p in report.get("priorities") or []
    ]
    ai = report.get("ai_risk") or {}
    idx = ai.get("index")
    model = ai.get("model") or {}
    evm = model.get("evaluation") or {}
    risk_rows = [
        [_mono(r["ref"]), _mono(r["server"]), _e(r["risk_class"].capitalize()), f"{r['score']:.0f}",
         f"{int(r['confidence'] * 100)}%",
         _e("; ".join(f"{d['label']} (+{d['impact']:.2f})" for d in r.get("drivers", [])[:3]) or "None above baseline")]
        for r in ai.get("sessions") or []
    ]
    blast_rows = [
        [_e(b["title"]), _sev(b["severity"]), str(b["direct_sessions"]), f"{b['dependent_clients']} ({b['clients_pct']:g}%)",
         f"{len(b['servers'])} ({b['servers_pct']:g}%)", f"{b['blast_score']:g}"]
        for b in report.get("blast_radius") or []
    ]
    index_line = ""
    if idx:
        distribution = ", ".join(f"{v} {k}" for k, v in idx["distribution"].items())
        index_line = f"<p>Capture risk index: {idx['index']:.0f} / 100 across {idx['sessions']} classified session(s) ({_e(distribution)}).</p>"
    risk = f"""
      {_h(1, 's7', '7', 'Risk Analysis and Prioritisation')}
      {_h(2, 's7-1', '7.1', 'Remediation Priority')}
      <p>Findings are ranked by a priority score combining severity, rule confidence, exposure of credentials or
      message content, the extent of dependent systems, recurrence and the risk class of the affected session.
      Tiers: P1 (70 and above) immediate; P2 (50 to 69) within one week; P3 (30 to 49) planned; P4 backlog.</p>
      {_table(["Rank", "ID", "Finding", "Severity", "Score", "Tier", "Contributing factors"], prio_rows,
              ["6%", "9%", "28%", "10%", "7%", "6%", "34%"], "small")}
      {cap('Remediation priority')}
      {_h(2, 's7-2', '7.2', 'Session Risk Classification')}
      <p>Each session was assigned one of five risk classes (minimal, low, medium, high, critical) by a
      gradient-boosted decision-tree classifier trained on {_e(model.get('training_rows'))} labelled sessions. On
      held-out data the classifier achieved {evm.get('holdout_accuracy', 0) * 100:.1f}% accuracy and a macro-averaged
      F1 score of {evm.get('holdout_macro_f1', 0):.3f}. Principal factors are Shapley attributions over groups of related
      features. The classification informs prioritisation only; all findings in Section 5 are determined by the rules
      described in Section 2.</p>
      {index_line}
      {_table(["Session", "Server", "Class", "Score", "Confidence", "Principal factors"], risk_rows,
              ["12%", "17%", "10%", "8%", "11%", "42%"], "small")}
      {cap('Highest-risk sessions')}
      {_h(2, 's7-3', '7.3', 'Extent of Impact')}
      <p>For each weakness, direct sessions are those that are themselves evidence of it; dependent clients are all
      observed clients relying on an affected server. Percentages refer to the observed environment only.</p>
      {_table(["Weakness", "Severity", "Direct sessions", "Dependent clients", "Servers", "Impact score"], blast_rows,
              ["36%", "11%", "12%", "15%", "13%", "13%"], "small")}
      {cap('Extent of impact by weakness')}"""

    # ------------------------------------------------------------------ 8 remediation
    plan_rows = [
        [str(st["step"]), _e(st["title"]), _e(st["owner"]), f"{st['effort']} / 3", _e(", ".join(st["addresses"])),
         f"{_e(st['score_before'])} → {_e(st['score_after'])}"]
        for st in steps
    ]

    def step_detail(st: dict) -> str:
        snippets = "".join(
            f'<p class="label">{_e(sn["file"])}</p><div class="code">'
            + "<br>".join(f"{_e(line['op'] if line['op'] != ' ' else '')} {_e(line['text'])}" for line in sn["lines"])
            + "</div>"
            for sn in st["snippets"][:3]
        )
        verify = "".join(f'<div class="code">{_e(v)}</div>' for v in st["verify"][:-1])
        target = ", ".join(f"{x['server']} ({x['name']})" for x in st["software"]) or ", ".join(st["servers"]) or "All servers"
        return f"""
        <div class="step">
          {_h(2, f"r-{st['step']}", f"8.{st['step'] + 1}", f"R{st['step']}: {st['title']}")}
          <table class="t meta">
            <colgroup><col style="width:22%"><col style="width:78%"></colgroup>
            <tr><th>Target</th><td>{_mono(target)}</td></tr>
            <tr><th>Owner / effort</th><td>{_e(st['owner'])}; effort {st['effort']} of 3</td></tr>
            <tr><th>Addresses</th><td>{_e(', '.join(st['addresses']))}</td></tr>
            <tr><th>References</th><td>{_e(', '.join(st['standards']))}</td></tr>
          </table>
          <h4>Configuration change</h4>{snippets}
          <h4>Verification</h4>{verify}
        </div>"""

    plan_table = (
        _table(["Step", "Action", "Owner", "Effort", "Findings addressed", "Projected score"], plan_rows,
               ["6%", "34%", "18%", "8%", "20%", "14%"], "small") + cap("Remediation plan")
        if steps else "<p>No configuration changes are required.</p>"
    )
    remediation = f"""
      {_h(1, 's8', '8', 'Remediation Plan')}
      {_h(2, 's8-1', '8.1', 'Plan Summary')}
      <p>The changes below are ordered by expected improvement relative to effort. The projected score after each
      change is obtained by re-evaluating the captured sessions as though the change had been in place, and should be
      confirmed by the verification steps and a subsequent capture.</p>
      {plan_table}
      {''.join(step_detail(st) for st in steps)}"""

    # ------------------------------------------------------------------ appendices
    session_rows = [
        [_mono(s["ref"]), _e(s["protocol"]), _mono(s["client"]), _mono(s["server"]),
         _e(_STATE_LABELS.get(s["encryption_state"], s["encryption_state"])), _e(s["tls_version"]),
         _mono((s["cipher_suite"] or "—").replace("TLS_", "")), f"{s['frames'][0]}–{s['frames'][1]}"]
        for s in sorted(email_sessions, key=lambda x: (x["protocol"] or "", x["ref"]))
    ]
    calc = po["calculation"]
    result = "—" if calc["result"] is None else f"{calc['result']:.2f}"
    calc_rows = [[_e(t["dimension"]), str(t["score"]), f"{t['weight']:.2f}", f"{t['product']:.2f}"] for t in calc["terms"]]
    calc_rows += [
        [f"<span class='muted'>{_e(x['dimension'])}</span>", "Excluded", f"({x['weight']:.2f})",
         f"<span class='muted'>{_e(x['reason'])}</span>"]
        for x in calc["excluded"]
    ]
    calc_rows.append(["<b>Total</b>", "", f"<b>{calc['denominator']:.2f}</b>",
                      f"<b>{calc['numerator']:.2f} ÷ {calc['denominator']:.2f} = {result}</b>"])
    appendices = f"""
      {_h(1, 'sa', 'A', 'Appendix A — Session Inventory')}
      {_table(["Session", "Protocol", "Client", "Server", "Encryption outcome", "TLS", "Cipher suite", "Frames"], session_rows,
              ["11%", "8%", "17%", "15%", "15%", "8%", "17%", "9%"], "small")}
      {cap('Reconstructed email sessions')}
      <div class="chapter-break"></div>
      {_h(1, 'sb', 'B', 'Appendix B — Scoring Methodology')}
      <p>The posture score is the weighted mean of the dimension scores that could be assessed from the evidence:
      score = Σ(dimension score × weight) ÷ Σ(weight). A dimension without supporting evidence is excluded rather
      than scored. The most severe finding affecting a dimension caps that dimension (critical 40, high 60, medium 75,
      low 90), so the score reflects the worst observed condition rather than an average.</p>
      {_table(["Dimension", "Score", "Weight", "Contribution"], calc_rows, ["34%", "14%", "14%", "38%"])}
      {cap('Posture score calculation')}
      {_h(1, 'sc', 'C', 'Appendix C — Glossary')}
      {_table(["Term", "Definition"], [[f"<b>{_e(a)}</b>", _e(b)] for a, b in _GLOSSARY], ["24%", "76%"])}
      <p class="end">End of report</p>"""

    body = cover + toc + "".join(
        f'<section class="chapter">{x}</section>'
        for x in (exec_summary, method, evidence, findings_summary, detailed, posture, risk, remediation, appendices)
    )

    running = f"{meta['title']} · {report_id}"
    font = '"Liberation Sans", Arial, sans-serif'
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{_e(meta['title'])} — {_e(report_id)}</title>
<style>
@page {{
  size: A4; margin: 22mm 18mm 20mm 18mm;
  @top-left {{ content: "{_e(running)}"; font: 7.5pt {font}; color: #6b7280; }}
  @top-right {{ content: "{_e(classification)}"; font: bold 7.5pt {font}; color: #6b7280; }}
  @bottom-left {{ content: "Evidence SHA-256 {ev['sha256'][:16]}…"; font: 7.5pt {font}; color: #6b7280; }}
  @bottom-right {{ content: "Page " counter(page) " of " counter(pages); font: 7.5pt {font}; color: #6b7280; }}
}}
@page :first {{
  @top-left {{ content: none; }} @top-right {{ content: none; }}
  @bottom-left {{ content: none; }} @bottom-right {{ content: none; }}
}}
* {{ box-sizing: border-box; }}
html {{ background: #e5e7eb; }}
body {{ margin: 24px auto; max-width: 210mm; background: #fff; color: #111827; padding: 18mm;
        font: 10pt/1.5 "Liberation Sans", Arial, Helvetica, sans-serif; box-shadow: 0 1px 4px rgba(0,0,0,.15); }}
@media print {{ html {{ background: #fff; }} body {{ margin: 0; padding: 0; max-width: none; box-shadow: none; }} }}
p {{ margin: 0 0 7pt; text-align: justify; }}
.mono, .code {{ font-family: "Liberation Mono", "DejaVu Sans Mono", Consolas, monospace; }}
.mono {{ font-size: 8.5pt; }}
.muted {{ color: #6b7280; }}
h2, h1 {{ page-break-after: avoid; }}
p + table.t, h2 + p, h2 + table.t {{ page-break-before: avoid; }}
h1 {{ font-size: 15pt; color: #0f2744; margin: 0 0 10pt; padding-bottom: 4pt; border-bottom: 1.5pt solid #0f2744; page-break-after: avoid; }}
h2 {{ font-size: 11.5pt; color: #0f2744; margin: 16pt 0 6pt; page-break-after: avoid; }}
h4 {{ font-size: 8.5pt; text-transform: uppercase; letter-spacing: .05em; color: #374151; margin: 9pt 0 3pt; page-break-after: avoid; }}
h1 .n, h2 .n {{ display: inline-block; min-width: 28pt; }}
.chapter, .toc {{ page-break-before: always; }}
.chapter-break {{ page-break-before: always; }}
ol.plain, ul.plain {{ margin: 0 0 8pt; padding-left: 16pt; }}
ol.plain li, ul.plain li {{ margin-bottom: 3pt; text-align: justify; }}
table.t {{ width: 100%; border-collapse: collapse; margin: 4pt 0 2pt; font-size: 9pt; table-layout: fixed; }}
table.t th {{ background: #0f2744; color: #fff; text-align: left; font-weight: bold; padding: 4pt 5pt; border: 0.6pt solid #0f2744; }}
table.t td {{ padding: 3.5pt 5pt; border: 0.6pt solid #c7ccd4; vertical-align: top; overflow-wrap: anywhere; }}
table.t tbody tr:nth-child(even) td {{ background: #f7f8fa; }}
table.t td.sev {{ font-weight: bold; }}
table.t.small {{ font-size: 8pt; }}
table.t.narrow {{ width: 45%; }}
table.t.kv2 td:first-child {{ background: #f1f3f6; font-weight: bold; }}
table.t.meta {{ font-size: 8.5pt; margin-bottom: 4pt; }}
table.t.meta th {{ background: #f1f3f6; color: #111827; border-color: #c7ccd4; }}
thead {{ display: table-header-group; }}
tr {{ page-break-inside: avoid; }}
body {{ counter-reset: tbl; }}
.cap {{ font-size: 8pt; color: #4b5563; font-style: italic; margin: 2pt 0 10pt; text-align: left; page-break-before: avoid; }}
.cap::before {{ counter-increment: tbl; content: "Table " counter(tbl) ". "; }}
td .mono {{ white-space: nowrap; }}
table.t.small td .mono {{ font-size: 7.5pt; }}
.label {{ font-size: 8pt; font-weight: bold; margin: 6pt 0 1pt; font-family: "Liberation Mono", monospace; text-align: left; }}
.code {{ font-size: 8pt; background: #f4f5f7; border: 0.6pt solid #d1d5db; padding: 5pt 6pt; margin: 2pt 0 6pt;
         white-space: pre-wrap; overflow-wrap: anywhere; line-height: 1.45; }}
.finding, .step {{ margin-bottom: 10pt; padding-bottom: 6pt; border-bottom: 0.6pt solid #d1d5db; }}
.end {{ text-align: center; color: #6b7280; margin-top: 24pt; }}
.cover {{ }}
.cover .org {{ font-size: 8.5pt; letter-spacing: .14em; text-transform: uppercase; color: #0f2744;
               border-bottom: 2pt solid #0f2744; padding-bottom: 6pt; }}
.cover-title {{ font-size: 24pt; font-weight: bold; color: #0f2744; line-height: 1.2; margin: 32mm 0 6pt; }}
.cover-sub {{ font-size: 11pt; color: #374151; margin-bottom: 16mm; }}
table.kv {{ width: 100%; border-collapse: collapse; font-size: 9.5pt; }}
table.kv th {{ text-align: left; width: 30%; padding: 3pt 0; color: #374151; vertical-align: top; }}
table.kv td {{ padding: 3pt 0; overflow-wrap: anywhere; }}
.doc-control {{ margin-top: 12mm; }}
.dc-title {{ font-weight: bold; font-size: 9pt; color: #0f2744; margin-bottom: 2pt; }}
table.sign td {{ height: 18pt; }}
.cover-foot {{ margin-top: 14mm; font-size: 7.5pt; color: #6b7280; border-top: 0.6pt solid #d1d5db; padding-top: 5pt; }}
.toc ul {{ list-style: none; padding: 0; margin: 0; }}
.toc li {{ padding: 5pt 0; border-bottom: 0.4pt dotted #9ca3af; font-size: 10.5pt; }}
.toc a {{ color: #111827; text-decoration: none; display: block; }}
.toc .tn {{ display: inline-block; min-width: 26pt; font-weight: bold; color: #0f2744; }}
.toc a::after {{ content: target-counter(attr(href), page); float: right; }}
@media screen {{ .chapter, .toc {{ border-top: 1px dashed #d1d5db; margin-top: 16mm; padding-top: 10mm; }} }}
</style></head>
<body>{body}</body></html>"""
