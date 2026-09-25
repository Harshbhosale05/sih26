"""Self-contained, print-ready HTML report.

On PDF: this template carries `@page` rules and print styles, so "Save as PDF"
in any browser produces the formal document. That deliberately avoids adding
WeasyPrint, which drags in cairo, pango and gdk-pixbuf — roughly 100 MB of
system libraries — to render a template we already have. If server-side PDF is
ever required, WeasyPrint consumes this same HTML unchanged.

Everything is inlined: no external CSS, fonts or scripts. The report has to
survive being emailed around and opened offline.
"""

from __future__ import annotations

from html import escape

_SEVERITY_COLOUR = {
    "CRITICAL": "#d03b3b",
    "HIGH": "#ec835a",
    "MEDIUM": "#fab219",
    "LOW": "#2a78d6",
    "INFO": "#898781",
}


def _band(score: int | None) -> str:
    if score is None:
        return "#898781"
    return "#0ca30c" if score >= 80 else "#fab219" if score >= 60 else "#ec835a" if score >= 40 else "#d03b3b"


def _e(value) -> str:
    return escape(str(value if value is not None else "—"))


def render(report: dict) -> str:
    ev, po, su, cv = report["evidence"], report["posture"], report["summary"], report["coverage"]

    dims = "".join(
        f"""<tr>
          <td><b>{_e(d['label'])}</b><div class="sub">{_e(d['standard'])}</div></td>
          <td class="num">{'NOT ASSESSED' if d['score'] is None else d['score']}</td>
          <td class="num">{'—' if d['coverage_pct'] is None else str(d['coverage_pct']) + '%'}</td>
          <td class="num">{int(d['weight']*100)}%</td>
          <td class="sub">{_e(d['detail'])}
            {''.join(f'<div>· {_e(c)}</div>' for c in d.get('contributors', []))}</td>
        </tr>"""
        for d in po["dimensions"]
    )

    sev_counts = " ".join(
        f'<span class="chip" style="color:{_SEVERITY_COLOUR[s]}">{s} {n}</span>'
        for s, n in su["by_severity"].items()
    )

    findings = "".join(
        f"""<div class="finding">
          <div class="fhead">
            <span class="ref">{_e(f['ref'])}</span>
            <span class="chip" style="color:{_SEVERITY_COLOUR.get(f['severity'], '#898781')}">{_e(f['severity'])}</span>
            <span class="ftitle">{_e(f['title'])}</span>
            <span class="chip">{_e(f['verdict'])}</span>
            <span class="chip">{int(f['confidence']*100)}% · {_e(f['detection_method'])}</span>
          </div>
          {f'<div class="sub">Session {_e(f["session_ref"])}</div>' if f.get('session_ref') else ''}
          <h4>Observed</h4><p>{_e(f['description'])}</p>
          <h4>Why this is the conclusion</h4><p>{_e(f['rationale'])}</p>
          {f"<h4>Remediation</h4><p>{_e(f['recommendation'])}</p>" if f.get('recommendation') else ''}
          {f"<h4>Standards</h4><p class='sub'>{' · '.join(_e(s) for s in f['standards'])}</p>" if f.get('standards') else ''}
          <h4>Evidence</h4>
          <table class="ev">
            <tr><td>Capture</td><td class="mono">{_e(ev['capture_ref'])} — {_e(ev['filename'])}</td></tr>
            <tr><td>Capture SHA-256</td><td class="mono">{_e(ev['sha256'])}</td></tr>
            <tr><td>Frames</td><td class="mono">{_e(', '.join(str(x) for x in f['evidence_frames']) or '—')}</td></tr>
            <tr><td>Wireshark filter</td><td class="mono">{_e(f['wireshark_filter'])}</td></tr>
          </table>
        </div>"""
        for f in report["findings"]
    )

    def _timeline(steps: list[dict]) -> str:
        if not steps:
            return '<span class="sub">no transitions recorded</span>'
        return " <b>→</b> ".join(
            f'{_e(t["state"])}<span class="sub"> f{t["frame"]}</span>' for t in steps
        )

    sessions = "".join(
        f"""<tr>
          <td class="mono">{_e(s['ref'])}</td><td>{_e(s['protocol'])}</td>
          <td class="mono">{_e(s['server'])}</td>
          <td>{_e(s['encryption_state'].replace('_', ' ').lower())}</td>
          <td class="small">{_e(s['starttls'])}</td>
          <td>{_e(s['tls_version'])}</td>
          <td class="mono small">{_e((s['cipher_suite'] or '—').replace('TLS_', ''))}</td>
          <td>{'—' if s['forward_secrecy'] is None else ('yes' if s['forward_secrecy'] else 'no')}</td>
          <td class="num">{s['frames'][0]}–{s['frames'][1]}</td>
        </tr>
        <tr class="tl"><td></td><td colspan="8" class="small">{_timeline(s['timeline'])}</td></tr>"""
        for s in report["sessions"]
    )

    calc = po["calculation"]
    calc_terms = "".join(
        f"""<tr><td>{_e(t['dimension'])}</td><td class="num">{t['score']}</td>
          <td class="num">× {t['weight']:.2f}</td><td class="num">= {t['product']:.1f}</td></tr>"""
        for t in calc["terms"]
    )
    calc_excluded = "".join(
        f"""<tr><td>{_e(x['dimension'])}</td><td class="num sub">excluded</td>
          <td class="num sub">({x['weight']:.2f})</td><td class="sub">{_e(x['reason'])}</td></tr>"""
        for x in calc["excluded"]
    )

    dns_block = ""
    if report.get("dns_policy") and report["dns_policy"].get("observed"):
        rows = "".join(
            f"""<tr><td class="mono">{_e(d['domain'])}</td>
              <td>{'yes' if d['mta_sts']['published'] else 'no' if d['mta_sts']['published'] is False else '—'}</td>
              <td>{'yes' if d['dane']['published'] else 'no' if d['dane']['published'] is False else '—'}</td>
              <td>{'yes' if d['tls_rpt']['published'] else 'no' if d['tls_rpt']['published'] is False else '—'}</td>
              <td>{_e(d['dmarc']['policy']) if d['dmarc']['published'] else 'no' if d['dmarc']['published'] is False else '—'}</td>
              <td class="mono small">{_e(', '.join(d['mx_hosts']) or '—')}</td></tr>"""
            for d in report["dns_policy"]["domains"]
        )
        dns_block = f"""<h2>5. Email policy (from DNS in this capture)</h2>
          <table><thead><tr><th>Domain</th><th>MTA-STS</th><th>DANE</th><th>TLS-RPT</th>
          <th>DMARC</th><th>MX</th></tr></thead><tbody>{rows}</tbody></table>
          <p class="sub">{_e(report['dns_policy']['note'])}</p>"""
    else:
        dns_block = """<h2>5. Email policy (from DNS in this capture)</h2>
          <p class="sub">No DNS traffic was present in this capture, so MTA-STS, DANE and
          DMARC policy could not be assessed. This is reported as undetermined — it does
          not indicate that these policies are absent from DNS.</p>"""

    pqc = report["pqc"]["readiness"]
    limitations = "".join(f"<li>{_e(x)}</li>" for x in report["limitations"])

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>{_e(report['report']['title'])} — {_e(ev['capture_ref'])}</title>
<style>
@page {{ size: A4; margin: 18mm 15mm; }}
* {{ box-sizing: border-box; }}
body {{ font: 10.5pt/1.5 system-ui, -apple-system, "Segoe UI", sans-serif;
        color: #111; margin: 0; padding: 24px; max-width: 1000px; margin: 0 auto; background:#fff; }}
h1 {{ font-size: 19pt; margin: 0 0 4px; }}
h2 {{ font-size: 13pt; margin: 26px 0 10px; padding-bottom: 5px; border-bottom: 2px solid #111;
      page-break-after: avoid; }}
h3 {{ font-size: 11pt; margin: 16px 0 6px; page-break-after: avoid; }}
h4 {{ font-size: 8pt; text-transform: uppercase; letter-spacing: .07em; color: #666;
      margin: 11px 0 3px; page-break-after: avoid; }}
p {{ margin: 0 0 6px; }}
.sub {{ color: #555; font-size: 9pt; }}
.mono {{ font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 8.5pt; }}
.small {{ font-size: 8pt; }}
.num {{ text-align: right; font-variant-numeric: tabular-nums; }}
.lede {{ color:#555; font-size: 10pt; margin-bottom: 18px; }}
table {{ width: 100%; border-collapse: collapse; margin: 8px 0 4px; }}
th {{ text-align: left; font-size: 8pt; text-transform: uppercase; letter-spacing: .06em;
      color: #666; border-bottom: 1.5px solid #999; padding: 5px 7px; }}
td {{ padding: 5px 7px; border-bottom: 1px solid #e4e4e0; vertical-align: top; }}
.hero {{ display: flex; gap: 22px; align-items: center; border: 1.5px solid #111;
         border-radius: 8px; padding: 16px 20px; margin: 14px 0 6px; }}
.hero .score {{ font-size: 44pt; font-weight: 600; line-height: 1; }}
.chip {{ font-size: 8pt; font-weight: 700; letter-spacing: .05em; border: 1px solid currentColor;
         border-radius: 3px; padding: 1px 5px; white-space: nowrap; }}
.ref {{ font-family: ui-monospace, Menlo, monospace; font-size: 9pt; color: #666; }}
.finding {{ border: 1px solid #ccc; border-radius: 7px; padding: 12px 14px; margin-bottom: 11px;
            page-break-inside: avoid; }}
.fhead {{ display: flex; gap: 9px; align-items: center; flex-wrap: wrap; margin-bottom: 4px; }}
.ftitle {{ font-weight: 600; flex: 1; min-width: 200px; }}
table.ev td {{ border: 0; padding: 2px 7px 2px 0; font-size: 9pt; }}
table.ev td:first-child {{ color: #666; width: 140px; }}
.box {{ border-left: 3px solid #666; background: #f6f6f3; padding: 10px 13px; margin: 10px 0;
        font-size: 9.5pt; page-break-inside: avoid; }}
footer {{ margin-top: 30px; padding-top: 10px; border-top: 1px solid #ccc;
          color: #666; font-size: 8.5pt; }}
.noprint {{ margin-bottom: 18px; }}
tr.tl td {{ border-bottom: 1px solid #e4e4e0; padding-top: 0; padding-bottom: 7px;
            color: #555; background: #fafaf8; }}
tr.tl b {{ color: #999; font-weight: 400; }}
@media print {{ .noprint {{ display: none; }} body {{ padding: 0; }} }}
</style></head><body>

<div class="noprint">
  <button onclick="window.print()" style="font:inherit;padding:7px 14px;border-radius:6px;
    border:1px solid #111;background:#111;color:#fff;cursor:pointer">Print / Save as PDF</button>
</div>

<h1>{_e(report['report']['title'])}</h1>
<div class="lede">
  {_e(report['report']['tool'])} · {_e(report['report']['problem_statement'])} ·
  {_e(report['report']['analysis_type'])}<br>
  Generated {_e(report['report']['generated_at'])}
</div>

<h2>1. Evidence manifest</h2>
<table>
  <tr><td style="width:180px">Capture</td><td>{_e(ev['capture_ref'])} — {_e(ev['filename'])}</td></tr>
  <tr><td>SHA-256</td><td class="mono">{_e(ev['sha256'])}</td></tr>
  <tr><td>Format / size</td><td>{_e(ev['format'])} · {_e(ev['size_bytes'])} bytes · {_e(ev['packet_count'])} packets</td></tr>
  <tr><td>Capture window</td><td>{_e(ev['first_packet_at'])} → {_e(ev['last_packet_at'])}</td></tr>
  <tr><td>Snaplen</td><td>{_e(ev['snaplen'])}{' (TRUNCATED — payload analysis may be incomplete)' if ev['snaplen_truncated'] else ''}</td></tr>
</table>
<p class="sub">Every finding in this report is traceable to this capture by the SHA-256 above.</p>

<h2>2. Security posture</h2>
<div class="hero">
  <div><div class="score" style="color:{_band(po['overall'])}">{po['overall'] if po['overall'] is not None else '—'}</div>
    <div class="sub">out of 100</div></div>
  <div><b>{po['dimensions_assessed']} of {po['dimensions_total']} dimensions assessed.</b>
    <div class="sub">{_e(po['note'])}</div></div>
</div>
<table><thead><tr><th>Dimension</th><th class="num">Score</th><th class="num">Coverage</th>
  <th class="num">Weight</th><th>Basis</th></tr></thead><tbody>{dims}</tbody></table>
<h3>2.1 How the score was calculated</h3>
<table><thead><tr><th>Dimension</th><th class="num">Score</th><th class="num">Weight</th>
  <th class="num">Contribution</th></tr></thead>
  <tbody>{calc_terms}{calc_excluded}
    <tr style="border-top:1.5px solid #999"><td><b>Total</b></td>
      <td class="num"><b>{calc['numerator']:.1f}</b></td>
      <td class="num"><b>÷ {calc['denominator']:.2f}</b></td>
      <td class="num"><b>= {calc['result']:.2f} → {calc['rounded']}</b></td></tr>
  </tbody></table>
<p class="sub">{_e(calc['formula'])}</p>
<div class="box"><b>Coverage is not the score.</b> {_e(calc['coverage_meaning'])}</div>

<div class="box"><b>How to read this score.</b> It is a coverage-weighted mean of the dimensions
that could actually be assessed from this capture. A dimension with no supporting evidence is
excluded entirely rather than scored — scoring it zero would blame the operator for a blind spot
in the evidence, and scoring it 100 would invent a clean result. Severe findings cap their
dimension, so the score reflects the worst observed state rather than an average that would
dilute a single critical exposure across many healthy sessions.</div>

<h2>3. Summary</h2>
<table>
  <tr><td style="width:180px">Email sessions</td><td>{su['sessions']} — {_e(', '.join(f'{k} {v}' for k, v in su['by_protocol'].items()))}</td></tr>
  <tr><td>Encryption outcomes</td><td>{_e(', '.join(f'{k.replace("_", " ").lower()} {v}' for k, v in su['by_encryption_state'].items()))}</td></tr>
  <tr><td>Findings</td><td>{su['findings']} &nbsp; {sev_counts}</td></tr>
  <tr><td>Undetermined verdicts</td><td>{su['unknown_verdicts']}</td></tr>
  <tr><td>Certificate coverage</td><td>{cv['certificate_observable']} of {cv['tls_sessions']} TLS sessions
    ({'—' if cv['certificate_coverage_pct'] is None else str(cv['certificate_coverage_pct']) + '%'})</td></tr>
</table>

<h2>4. Findings</h2>
{findings or '<p class="sub">No findings.</p>'}

{dns_block}

<h2>6. Post-quantum migration readiness</h2>
<table>
  <tr><td style="width:280px">TLS sessions analysed</td><td class="num">{pqc['tls_sessions']}</td></tr>
  <tr><td>Clients offering hybrid PQC key exchange</td><td class="num">{pqc['clients_offering_pqc']} ({pqc['clients_offering_pqc_pct']}%)</td></tr>
  <tr><td>Servers selecting hybrid PQC</td><td class="num">{pqc['servers_selecting_pqc']} ({pqc['servers_selecting_pqc_pct']}%)</td></tr>
  <tr><td>Sessions without forward secrecy</td><td class="num">{pqc['sessions_without_forward_secrecy']}</td></tr>
</table>
<div class="box">{_e(report['pqc']['framing'])}</div>

<h2>7. Sessions</h2>
<p class="sub">The <b>STARTTLS</b> column says how each session reached its outcome, which is
usually the actionable part: "advertised → not used" is a client problem, "not advertised" is a
server problem, and "capability mangled" is a network problem — same cleartext result, three
different fixes. The grey row beneath each session is its encryption-state timeline with the
frame that caused each transition.</p>
<table><thead><tr><th>Session</th><th>Proto</th><th>Server</th><th>Encryption state</th>
  <th>STARTTLS</th><th>TLS</th><th>Cipher</th><th>PFS</th><th class="num">Frames</th></tr></thead>
  <tbody>{sessions}</tbody></table>

<h2>8. Scope and limitations</h2>
<ul class="sub">{limitations}</ul>

<footer>
  SecureMailScope · passive cryptographic posture assessment · SIH26159 (NTRO).<br>
  Analysis is deterministic: the same capture produces the same findings and the same score.
  Findings are produced by deterministic rules; machine learning contributes context only and
  never a verdict.
</footer>
</body></html>"""
