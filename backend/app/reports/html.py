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

_SEVERITY = {
    # (fill, text-on-fill)
    "CRITICAL": ("#c62828", "#fff"),
    "HIGH": ("#e8692f", "#fff"),
    "MEDIUM": ("#f2b01e", "#1a1a1a"),
    "LOW": ("#2a78d6", "#fff"),
    "INFO": ("#7b8794", "#fff"),
}

_RISK_TO_SEVERITY = {
    "critical": "CRITICAL", "high": "HIGH", "medium": "MEDIUM", "low": "LOW",
    "ok": None, "unknown": "INFO",
}


def _band(score: int | None) -> str:
    if score is None:
        return "#7b8794"
    return "#1a8f3c" if score >= 80 else "#d99100" if score >= 60 else "#e8692f" if score >= 40 else "#c62828"


def _rating(score: int | None, critical: int = 0) -> str:
    if score is None:
        return "Not assessable"
    # A single unresolved critical finding outranks any average.
    if critical:
        return f"Action required — {critical} critical finding{'s' if critical > 1 else ''}"
    return "Strong" if score >= 80 else "Moderate" if score >= 60 else "Weak" if score >= 40 else "Critical"


def _e(value) -> str:
    return escape(str(value if value is not None else "—"))


def _badge(severity: str) -> str:
    fill, ink = _SEVERITY.get(severity, _SEVERITY["INFO"])
    return f'<span class="badge" style="background:{fill};color:{ink}">{_e(severity)}</span>'


def _ok_badge(label: str = "OK") -> str:
    return f'<span class="badge" style="background:#1a8f3c;color:#fff">{_e(label)}</span>'


def _bar(value: float | None, colour: str | None = None) -> str:
    if value is None:
        return '<div class="bar"><div style="width:0"></div></div>'
    colour = colour or _band(value)
    return f'<div class="bar"><div style="width:{max(1, min(100, value))}%;background:{colour}"></div></div>'


def _section(number: int, title: str, body: str, lede: str = "", page_break: bool = False) -> str:
    return f"""<section class="section{' pb' if page_break else ''}">
      <h2><span class="num">{number}</span>{_e(title)}</h2>
      {f'<p class="lede">{lede}</p>' if lede else ''}
      {body}
    </section>"""


def render(report: dict) -> str:
    meta, ev, po, su, cv = (
        report["report"], report["evidence"], report["posture"], report["summary"], report["coverage"],
    )
    pqc_r = report.get("pqc_readiness") or {}
    stls = report.get("starttls") or {}
    blast = report.get("blast_radius") or []
    findings_list = report["findings"]
    fails = [f for f in findings_list if f["verdict"] == "FAIL"]
    critical = sum(1 for f in fails if f["severity"] == "CRITICAL")
    rating_colour = "#c62828" if critical else None

    # ------------------------------------------------------------------ Summary
    sev_cells = "".join(
        f'<div class="sevcell"><div class="sevn" style="color:{_SEVERITY[s][0]}">{su["by_severity"].get(s, 0)}</div>'
        f'<div class="sevl">{s.title()}</div></div>'
        for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
    )
    adoption = (stls.get("summary") or {}).get("adoption_pct")
    kpis = f"""
    <div class="kpis">
      <div class="kpi">
        <div class="kl">Security posture</div>
        <div class="kval" style="color:{_band(po['overall'])}">{po['overall'] if po['overall'] is not None else '—'}<span>/100</span></div>
        <div class="ks">{_rating(po['overall'], critical)} · {po['dimensions_assessed']} of {po['dimensions_total']} dimensions assessed</div>
      </div>
      <div class="kpi">
        <div class="kl">PQC readiness</div>
        <div class="kval" style="color:{_band(pqc_r.get('score'))}">{pqc_r.get('score') if pqc_r.get('score') is not None else '—'}<span>/100</span></div>
        <div class="ks">{_e(pqc_r.get('level_label') or 'Not assessable')} · {_e(pqc_r.get('hndl_exposed_pct'))}% harvest-now-decrypt-later exposed</div>
      </div>
      <div class="kpi">
        <div class="kl">STARTTLS adoption</div>
        <div class="kval" style="color:{_band(adoption)}">{'—' if adoption is None else f'{adoption:g}'}<span>{'' if adoption is None else '%'}</span></div>
        <div class="ks">{(stls.get('summary') or {}).get('upgraded', 0)} of {(stls.get('summary') or {}).get('observable', 0)} plaintext-start sessions upgraded</div>
      </div>
      <div class="kpi">
        <div class="kl">Findings</div>
        <div class="sevrow">{sev_cells}</div>
        <div class="ks">{su['findings']} total · {su['unknown_verdicts']} undetermined</div>
      </div>
    </div>"""

    top = fails[:5]
    key_risks = "".join(
        f"""<tr><td style="width:92px">{_badge(f['severity'])}</td>
          <td><b>{_e(f['title'])}</b><div class="sub">{_e(f['description'])}</div></td>
          <td class="sub" style="width:34%">{_e((f.get('recommendation') or '').split('. ')[0])}.</td></tr>"""
        for f in top
    ) or '<tr><td colspan="3" class="sub">No failing findings in this capture.</td></tr>'

    executive = f"""{kpis}
      <h3>Key risks and first actions</h3>
      <table class="grid"><thead><tr><th>Severity</th><th>Risk</th><th>First action</th></tr></thead>
      <tbody>{key_risks}</tbody></table>
      <div class="note"><b>Scope.</b> Passive analysis of {su['sessions']} email session(s)
      ({_e(', '.join(f'{k} {v}' for k, v in su['by_protocol'].items()) or 'none')}) in capture
      {_e(ev['capture_ref'])}. No server was contacted. Every finding below is linked to the frames that prove it.</div>"""

    # ------------------------------------------------------------------ Evidence
    evidence = f"""<table class="kv">
      <tr><td>Capture</td><td>{_e(ev['capture_ref'])} — {_e(ev['filename'])}</td></tr>
      <tr><td>SHA-256</td><td class="mono">{_e(ev['sha256'])}</td></tr>
      <tr><td>Format / size</td><td>{_e(ev['format'])} · {_e(ev['size_bytes'])} bytes · {_e(ev['packet_count'])} packets</td></tr>
      <tr><td>Capture window</td><td>{_e(ev['first_packet_at'])} → {_e(ev['last_packet_at'])}</td></tr>
      <tr><td>Snaplen</td><td>{_e(ev['snaplen'])}{' — TRUNCATED, payload analysis may be incomplete' if ev['snaplen_truncated'] else ''}</td></tr>
      <tr><td>Certificate coverage</td><td>{cv['certificate_observable']} of {cv['tls_sessions']} TLS sessions
        ({'—' if cv['certificate_coverage_pct'] is None else str(cv['certificate_coverage_pct']) + '%'})</td></tr>
    </table>
    <p class="sub">Every finding in this report is traceable to this capture by the SHA-256 above.</p>"""

    # ------------------------------------------------------------------ Posture
    dims = "".join(
        f"""<tr>
          <td><b>{_e(d['label'])}</b><div class="sub">{_e(d['standard'])}</div></td>
          <td class="c">{'<span class="na">NOT ASSESSED</span>' if d['score'] is None else f"<b style='color:{_band(d['score'])}'>{d['score']}</b>"}</td>
          <td style="width:120px">{_bar(d['score'])}</td>
          <td class="c">{'—' if d['coverage_pct'] is None else str(d['coverage_pct']) + '%'}</td>
          <td class="c">{int(d['weight']*100)}%</td>
          <td class="sub">{''.join(f'<div>· {_e(c)}</div>' for c in d.get('contributors', [])) or _e(d['detail'])}</td>
        </tr>"""
        for d in po["dimensions"]
    )
    calc = po["calculation"]
    calc_terms = "".join(
        f"""<tr><td>{_e(t['dimension'])}</td><td class="c">{t['score']}</td>
          <td class="c">× {t['weight']:.2f}</td><td class="c">= {t['product']:.1f}</td></tr>"""
        for t in calc["terms"]
    )
    calc_excluded = "".join(
        f"""<tr class="muted"><td>{_e(x['dimension'])}</td><td class="c">excluded</td>
          <td class="c">({x['weight']:.2f})</td><td class="sub">{_e(x['reason'])}</td></tr>"""
        for x in calc["excluded"]
    )
    posture = f"""
    <div class="hero">
      <div class="score" style="color:{_band(po['overall'])}">{po['overall'] if po['overall'] is not None else '—'}<span>/100</span></div>
      <div><div class="rating" style="background:{rating_colour or _band(po['overall'])}">{_rating(po['overall'], critical)}</div>
        <div class="sub" style="margin-top:6px">{_e(po['note'])}</div></div>
    </div>
    <table class="grid"><thead><tr><th>Dimension</th><th class="c">Score</th><th></th><th class="c">Coverage</th>
      <th class="c">Weight</th><th>Basis</th></tr></thead><tbody>{dims}</tbody></table>
    <h3>How the score was calculated</h3>
    <table class="grid"><thead><tr><th>Dimension</th><th class="c">Score</th><th class="c">Weight</th>
      <th class="c">Contribution</th></tr></thead>
      <tbody>{calc_terms}{calc_excluded}
        <tr class="total"><td>Total</td><td class="c">{calc['numerator']:.1f}</td>
          <td class="c">÷ {calc['denominator']:.2f}</td>
          <td class="c">= {'—' if calc['result'] is None else f"{calc['result']:.2f} → {calc['rounded']}"}</td></tr>
      </tbody></table>
    <div class="note"><b>Reading the score.</b> {_e(calc['formula'])}. A dimension with no supporting
    evidence is excluded rather than scored, and a severe finding caps its dimension, so the score
    reflects the worst observed state rather than an average. {_e(calc['coverage_meaning'])}</div>"""

    # ------------------------------------------------------------------ Findings
    def finding_card(f: dict) -> str:
        fill, _ = _SEVERITY.get(f["severity"], _SEVERITY["INFO"])
        return f"""<div class="finding" style="border-left-color:{fill}">
          <div class="fhead">
            {_badge(f['severity'])}
            <span class="ref">{_e(f['ref'])}</span>
            <span class="ftitle">{_e(f['title'])}</span>
            <span class="tag">{_e(f['verdict'])}</span>
            <span class="tag">{int(f['confidence']*100)}% confidence</span>
          </div>
          <div class="cols">
            <div><h4>Observed</h4><p>{_e(f['description'])}</p></div>
            <div><h4>Why this is the conclusion</h4><p>{_e(f['rationale'])}</p></div>
          </div>
          {f"<div class='fix'><h4>Remediation</h4><p>{_e(f['recommendation'])}</p></div>" if f.get('recommendation') else ''}
          <table class="ev">
            {f"<tr><td>Session</td><td class='mono'>{_e(f['session_ref'])} · {f['affected_sessions']} session(s) affected</td></tr>" if f.get('session_ref') else ''}
            <tr><td>Evidence frames</td><td class="mono">{_e(', '.join(str(x) for x in f['evidence_frames']) or '—')}</td></tr>
            <tr><td>Wireshark filter</td><td class="mono">{_e(f['wireshark_filter'])}</td></tr>
            {f"<tr><td>Standards</td><td>{' · '.join(_e(s) for s in f['standards'])}</td></tr>" if f.get('standards') else ''}
            <tr><td>Method</td><td>{_e(f['detection_method'])} rule</td></tr>
          </table>
        </div>"""

    findings = "".join(finding_card(f) for f in findings_list) or '<p class="sub">No findings.</p>'

    # ------------------------------------------------------------------ Blast radius
    blast_rows = "".join(
        f"""<tr><td>{_badge(r['severity'])}</td><td><b>{_e(r['title'])}</b>
          <div class="sub">{_e(', '.join(r['finding_refs']))}</div></td>
          <td class="c">{r['direct_sessions']}</td>
          <td class="c">{r['dependent_clients']} <span class="sub">({r['clients_pct']:g}%)</span></td>
          <td class="c">{len(r['servers'])} <span class="sub">({r['servers_pct']:g}%)</span></td>
          <td style="width:110px">{_bar(r['blast_score'], '#2a78d6')}<div class="sub c">{r['blast_score']:g}</div></td></tr>"""
        for r in blast
    )
    blast_block = (
        f"""<table class="grid"><thead><tr><th>Severity</th><th>Weakness</th><th class="c">Direct sessions</th>
        <th class="c">Dependent clients</th><th class="c">Servers</th><th>Blast score</th></tr></thead>
        <tbody>{blast_rows}</tbody></table>
        <p class="sub">Direct = sessions that are themselves evidence. Dependent = every observed client relying on an
        affected server. Blast score = severity weight × (0.6 × direct share + 0.4 × dependent client share) × 100,
        over the observed environment only.</p>"""
        if blast else '<p class="sub">No failing weakness with a measurable reach.</p>'
    )

    # ------------------------------------------------------------------ STARTTLS
    funnel = stls.get("funnel") or []
    start = (funnel[0]["count"] if funnel else 0) or 1
    funnel_rows = "".join(
        f"""<tr><td>{_e(f['label'])}</td><td class="c">{f['count']}</td>
          <td style="width:45%">{_bar(100 * f['count'] / start, '#2a78d6')}</td>
          <td class="c">{'—' if f['pct_of_start'] is None else f"{f['pct_of_start']:g}%"}</td></tr>"""
        for f in funnel
    )
    fp_rows = "".join(
        f"""<tr><td>{_ok_badge() if f['severity'] == 'ok' else _badge(_RISK_TO_SEVERITY.get(f['severity']) or 'INFO')}</td>
          <td><b>{_e(f['label'])}</b><div class="sub">{_e(f['explanation'])}</div></td>
          <td class="c">{_e({'server': 'Server', 'client': 'Client', 'network': 'Network', 'both': 'Client + server'}.get(f['owner'], '—'))}</td>
          <td class="c">{f['count']} <span class="sub">({f['pct']:g}%)</span></td></tr>"""
        for f in stls.get("failure_points") or []
    )
    starttls_block = (
        f"""<h3>Upgrade funnel</h3>
        <table class="grid"><thead><tr><th>Stage</th><th class="c">Sessions</th><th></th><th class="c">Of start</th></tr></thead>
        <tbody>{funnel_rows}</tbody></table>
        <h3>Where upgrades stop</h3>
        <table class="grid"><thead><tr><th>Status</th><th>Outcome</th><th class="c">Fix owner</th><th class="c">Sessions</th></tr></thead>
        <tbody>{fp_rows}</tbody></table>"""
        if funnel and (stls.get("summary") or {}).get("starttls_eligible")
        else '<p class="sub">No plaintext-start sessions — every session used implicit TLS, so there is no STARTTLS behaviour to assess.</p>'
    )

    # ------------------------------------------------------------------ PQC
    pqc_legacy = report["pqc"]["readiness"]
    exposure_rows = "".join(
        f"""<tr><td>{_ok_badge('SAFE') if t['tier'] == 'pqc_hybrid' else _badge(_RISK_TO_SEVERITY.get(t['risk']) or 'INFO')}</td>
          <td><b>{_e(t['label'])}</b><div class="sub">{_e(t['explanation'])}</div></td>
          <td class="c">{t['sessions']}</td><td class="c">{t['pct']:g}%</td></tr>"""
        for t in pqc_r.get("exposure") or []
    )
    comp_rows = "".join(
        f"""<tr><td>{_e(c['label'])}</td><td class="c">{int(c['weight']*100)}%</td>
          <td class="c">{'—' if c['score'] is None else c['score']}</td>
          <td style="width:120px">{_bar(c['score'])}</td><td class="c sub">{c['observed']}/{c['total']}</td></tr>"""
        for c in pqc_r.get("components") or []
    )
    actions = "".join(
        f"<li><b>{_e(a['title'])}.</b> <span class='sub'>{_e(a['detail'])}</span></li>"
        for a in pqc_r.get("actions") or []
    )
    pqc_block = f"""
    <div class="hero">
      <div class="score" style="color:{_band(pqc_r.get('score'))}">{pqc_r.get('score') if pqc_r.get('score') is not None else '—'}<span>/100</span></div>
      <div><div class="rating" style="background:{_band(pqc_r.get('score'))}">{_e(pqc_r.get('level_label') or 'Not assessable')}</div>
        <div class="sub" style="margin-top:6px">{_e(pqc_r.get('cap_note') or pqc_r.get('framing'))}</div></div>
    </div>
    <h3>Harvest-now-decrypt-later exposure</h3>
    <table class="grid"><thead><tr><th>Risk</th><th>Tier</th><th class="c">Sessions</th><th class="c">Share</th></tr></thead>
    <tbody>{exposure_rows}</tbody></table>
    <h3>Readiness components</h3>
    <table class="grid"><thead><tr><th>Component</th><th class="c">Weight</th><th class="c">Score</th><th></th><th class="c">Evidence</th></tr></thead>
    <tbody>{comp_rows}</tbody></table>
    {f'<h3>Migration plan</h3><ol class="actions">{actions}</ol>' if actions else ''}
    <div class="note">{_e(report['pqc']['framing'])} Clients offering hybrid PQC: {pqc_legacy['clients_offering_pqc']}
    ({pqc_legacy['clients_offering_pqc_pct']}%); servers selecting it: {pqc_legacy['servers_selecting_pqc']}
    ({pqc_legacy['servers_selecting_pqc_pct']}%).</div>"""

    # ------------------------------------------------------------------ DNS
    if report.get("dns_policy") and report["dns_policy"].get("observed"):
        def yn(v):
            return '<span class="yes">Yes</span>' if v else '<span class="no">No</span>' if v is False else '—'
        rows = "".join(
            f"""<tr><td class="mono">{_e(d['domain'])}</td>
              <td class="c">{yn(d['mta_sts']['published'])}</td><td class="c">{yn(d['dane']['published'])}</td>
              <td class="c">{yn(d['tls_rpt']['published'])}</td>
              <td class="c">{_e(d['dmarc']['policy']) if d['dmarc']['published'] else yn(d['dmarc']['published'])}</td>
              <td class="mono">{_e(', '.join(d['mx_hosts']) or '—')}</td></tr>"""
            for d in report["dns_policy"]["domains"]
        )
        dns_block = f"""<table class="grid"><thead><tr><th>Domain</th><th class="c">MTA-STS</th><th class="c">DANE</th>
          <th class="c">TLS-RPT</th><th class="c">DMARC</th><th>MX</th></tr></thead><tbody>{rows}</tbody></table>
          <p class="sub">{_e(report['dns_policy']['note'])}</p>"""
    else:
        dns_block = """<div class="note">No DNS traffic was present in this capture, so MTA-STS, DANE and DMARC
          policy could not be assessed. This is reported as undetermined — it does not indicate that these
          policies are absent from DNS.</div>"""

    # ------------------------------------------------------------------ Sessions
    def _timeline(steps: list[dict]) -> str:
        if not steps:
            return "no transitions recorded"
        return " → ".join(f'{_e(t["state"])} <span class="fr">f{t["frame"]}</span>' for t in steps)

    sessions = "".join(
        f"""<tr>
          <td class="mono" style="white-space:nowrap"><b>{_e(s['ref'])}</b></td><td>{_e(s['protocol'])}</td>
          <td class="mono" style="white-space:nowrap">{_e(s['server'])}</td>
          <td>{_e(s['encryption_state'].replace('_', ' ').lower())}</td>
          <td class="sub">{_e(s['starttls'])}</td>
          <td>{_e(s['tls_version'])}</td>
          <td class="mono">{_e((s['cipher_suite'] or '—').replace('TLS_', ''))}</td>
          <td class="c">{'—' if s['forward_secrecy'] is None else ('Yes' if s['forward_secrecy'] else 'No')}</td>
          <td class="c">{s['frames'][0]}–{s['frames'][1]}</td>
        </tr>
        <tr class="tl"><td></td><td colspan="8">{_timeline(s['timeline'])}</td></tr>"""
        for s in report["sessions"]
    )
    sessions_block = f"""<table class="grid small"><thead><tr><th>Session</th><th>Proto</th><th>Server</th>
      <th>Encryption</th><th>STARTTLS path</th><th>TLS</th><th>Cipher</th><th class="c">PFS</th><th class="c">Frames</th></tr></thead>
      <tbody>{sessions}</tbody></table>
      <p class="sub">The shaded row under each session is its encryption-state timeline with the frame that caused each transition.</p>"""

    limitations = "".join(f"<li>{_e(x)}</li>" for x in report["limitations"])

    body = "".join([
        _section(1, "Executive summary", executive),
        _section(2, "Evidence manifest", evidence),
        _section(3, "Security posture", posture, "How secure is this communication against today's attacker.", True),
        _section(4, "Findings", findings,
                 "Each finding states what was observed, why it follows, how to fix it, and where the proof is.", True),
        _section(5, "Blast radius", blast_block, "What depends on each weakness across the observed environment."),
        _section(6, "STARTTLS upgrade analysis", starttls_block,
                 "Where opportunistic encryption succeeds or fails, and who owns the fix."),
        _section(7, "Post-quantum readiness", pqc_block,
                 "How much of this traffic survives an attacker who records it now and decrypts it later.", True),
        _section(8, "Email policy (DNS)", dns_block),
        _section(9, "Sessions", sessions_block, "", True),
        _section(10, "Scope and limitations", f'<ul class="lim">{limitations}</ul>'),
    ])

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{_e(meta['title'])} — {_e(ev['capture_ref'])}</title>
<style>
@page {{ size: A4; margin: 14mm 13mm 16mm; }}
* {{ box-sizing: border-box; -webkit-print-color-adjust: exact; print-color-adjust: exact; }}
body {{ font: 10pt/1.5 system-ui, -apple-system, "Segoe UI", Roboto, sans-serif; color: #1c2430;
        margin: 0; background: #eef1f5; }}
.page {{ max-width: 1040px; margin: 24px auto; background: #fff; border: 1px solid #d5dbe3;
         border-radius: 10px; overflow: hidden; box-shadow: 0 4px 24px rgba(15,42,74,.08); }}
.masthead {{ background: linear-gradient(120deg, #0f2a4a, #173f6d); color: #fff; padding: 26px 34px 22px; }}
.brand {{ display: flex; align-items: center; justify-content: space-between; gap: 12px; flex-wrap: wrap; }}
.logo {{ display: flex; align-items: center; gap: 10px; font-weight: 700; font-size: 13pt; letter-spacing: .01em; }}
.logo i {{ display: inline-flex; width: 30px; height: 30px; border-radius: 7px; background: #2a78d6;
           align-items: center; justify-content: center; font-style: normal; font-size: 14pt; }}
.class {{ border: 1px solid rgba(255,255,255,.5); border-radius: 4px; padding: 3px 9px;
          font-size: 7.5pt; letter-spacing: .1em; font-weight: 700; }}
.masthead h1 {{ font-size: 20pt; margin: 18px 0 4px; font-weight: 650; letter-spacing: -.01em; }}
.masthead .subt {{ color: #b9cbe2; font-size: 9.5pt; }}
.metabar {{ display: grid; grid-template-columns: repeat(4, 1fr); border-bottom: 1px solid #d5dbe3; background: #f7f9fb; }}
.metabar div {{ padding: 11px 16px; border-right: 1px solid #e3e8ee; font-size: 8.5pt; color: #5b6878; }}
.metabar div:last-child {{ border-right: 0; }}
.metabar b {{ display: block; color: #1c2430; font-size: 9.5pt; margin-top: 2px; word-break: break-all; }}
.content {{ padding: 8px 34px 26px; }}
.section {{ margin-top: 26px; }}
h2 {{ display: flex; align-items: center; gap: 10px; font-size: 13.5pt; color: #0f2a4a; margin: 0 0 6px;
      padding-bottom: 8px; border-bottom: 2px solid #0f2a4a; page-break-after: avoid; }}
h2 .num {{ display: inline-flex; width: 24px; height: 24px; border-radius: 6px; background: #0f2a4a; color: #fff;
           font-size: 10pt; align-items: center; justify-content: center; }}
h3 {{ font-size: 10.5pt; color: #0f2a4a; margin: 18px 0 6px; page-break-after: avoid; }}
h4 {{ font-size: 7.5pt; text-transform: uppercase; letter-spacing: .08em; color: #5b6878; margin: 0 0 3px; }}
p {{ margin: 0 0 6px; }}
.lede {{ color: #5b6878; font-size: 9.5pt; margin: 4px 0 10px; }}
.sub {{ color: #5b6878; font-size: 8.5pt; }}
.mono {{ font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 8.3pt; word-break: break-all; }}
.c {{ text-align: center; font-variant-numeric: tabular-nums; }}
table {{ width: 100%; border-collapse: collapse; margin: 6px 0; }}
table.grid {{ border: 1px solid #d5dbe3; border-radius: 6px; overflow: hidden; }}
table.grid th {{ background: #eef2f7; color: #334155; text-align: left; font-size: 7.6pt; text-transform: uppercase;
                 letter-spacing: .06em; padding: 7px 9px; border-bottom: 1px solid #d5dbe3; }}
table.grid th.c {{ text-align: center; }}
table.grid td {{ padding: 7px 9px; border-bottom: 1px solid #e6eaf0; vertical-align: top; }}
table.grid tbody tr:nth-child(even) td {{ background: #fafbfd; }}
table.grid tr.total td {{ background: #eef2f7 !important; font-weight: 700; border-top: 1.5px solid #9aa7b6; }}
table.grid tr.muted td {{ color: #8793a3; }}
table.small td {{ font-size: 8.5pt; }}
table.kv {{ border: 1px solid #d5dbe3; }}
table.kv td {{ padding: 7px 10px; border-bottom: 1px solid #e6eaf0; }}
table.kv td:first-child {{ width: 190px; background: #f4f6f9; color: #475569; font-weight: 600; font-size: 8.8pt; }}
.badge {{ display: inline-block; font-size: 7.3pt; font-weight: 800; letter-spacing: .06em; border-radius: 4px;
          padding: 2px 7px; white-space: nowrap; }}
.tag {{ font-size: 7.5pt; font-weight: 600; color: #475569; border: 1px solid #cbd3dd; border-radius: 4px; padding: 1px 6px; }}
.na {{ font-size: 7.5pt; font-weight: 700; color: #8793a3; letter-spacing: .05em; }}
.bar {{ height: 7px; background: #e6eaf0; border-radius: 4px; overflow: hidden; margin-top: 5px; }}
.bar div {{ height: 100%; border-radius: 4px; }}
.kpis {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 10px; margin: 12px 0 4px; }}
.kpi {{ border: 1px solid #d5dbe3; border-radius: 8px; padding: 12px 14px; background: #fff; border-top: 3px solid #0f2a4a; }}
.kl {{ font-size: 7.6pt; text-transform: uppercase; letter-spacing: .08em; color: #5b6878; font-weight: 700; }}
.kval {{ font-size: 26pt; font-weight: 700; line-height: 1.1; margin: 6px 0 3px; }}
.kval span {{ font-size: 10pt; color: #8793a3; font-weight: 600; margin-left: 2px; }}
.ks {{ font-size: 8pt; color: #5b6878; }}
.sevrow {{ display: flex; gap: 4px; margin: 8px 0 6px; }}
.sevcell {{ flex: 1; text-align: center; border: 1px solid #e6eaf0; border-radius: 5px; padding: 3px 0; }}
.sevn {{ font-size: 14pt; font-weight: 800; line-height: 1.2; }}
.sevl {{ font-size: 6.5pt; color: #5b6878; text-transform: uppercase; letter-spacing: .04em; }}
.hero {{ display: flex; gap: 22px; align-items: center; border: 1px solid #d5dbe3; border-radius: 8px;
         padding: 14px 20px; margin: 8px 0 10px; background: #f7f9fb; }}
.hero .score {{ font-size: 40pt; font-weight: 800; line-height: 1; white-space: nowrap; }}
.hero .score span {{ font-size: 12pt; color: #8793a3; font-weight: 600; }}
.rating {{ display: inline-block; color: #fff; font-weight: 700; font-size: 9pt; border-radius: 4px; padding: 2px 10px; }}
.note {{ border: 1px solid #cfdcec; border-left: 4px solid #2a78d6; background: #f3f7fc; border-radius: 6px;
         padding: 10px 13px; margin: 12px 0 4px; font-size: 9pt; page-break-inside: avoid; }}
.finding {{ border: 1px solid #d5dbe3; border-left: 5px solid; border-radius: 8px; padding: 12px 15px; margin: 12px 0;
            page-break-inside: avoid; background: #fff; }}
.fhead {{ display: flex; gap: 8px; align-items: center; flex-wrap: wrap; padding-bottom: 9px; margin-bottom: 9px;
          border-bottom: 1px solid #e6eaf0; }}
.ref {{ font-family: ui-monospace, Menlo, monospace; font-size: 8.5pt; color: #5b6878; }}
.ftitle {{ font-weight: 700; flex: 1; min-width: 200px; font-size: 10.5pt; }}
.cols {{ display: grid; grid-template-columns: 1fr 1fr; gap: 16px; }}
.fix {{ background: #f0f8f2; border: 1px solid #cfe7d6; border-radius: 6px; padding: 8px 11px; margin: 8px 0; }}
.fix h4 {{ color: #1a6b33; }}
table.ev {{ margin-top: 6px; }}
table.ev td {{ padding: 3px 8px 3px 0; font-size: 8.5pt; border: 0; vertical-align: top; }}
table.ev td:first-child {{ color: #5b6878; width: 130px; font-weight: 600; }}
tr.tl td {{ background: #f4f6f9 !important; color: #475569; font-size: 8pt; padding-top: 3px; padding-bottom: 7px; }}
tr.tl .fr {{ color: #8793a3; font-family: ui-monospace, Menlo, monospace; font-size: 7.5pt; }}
.yes {{ color: #1a8f3c; font-weight: 700; }} .no {{ color: #c62828; font-weight: 700; }}
ol.actions {{ margin: 4px 0; padding-left: 20px; }} ol.actions li {{ margin: 4px 0; }}
ul.lim {{ margin: 6px 0; padding-left: 18px; color: #475569; font-size: 9pt; }} ul.lim li {{ margin: 4px 0; }}
footer {{ border-top: 1px solid #d5dbe3; background: #f7f9fb; padding: 14px 34px; color: #5b6878; font-size: 8pt;
          display: flex; justify-content: space-between; gap: 12px; flex-wrap: wrap; }}
.toolbar {{ max-width: 1040px; margin: 18px auto -8px; display: flex; justify-content: flex-end; gap: 8px; }}
.toolbar button {{ font: 600 9.5pt system-ui, sans-serif; padding: 8px 16px; border-radius: 7px; border: 0;
                   background: #0f2a4a; color: #fff; cursor: pointer; }}
@media (max-width: 760px) {{
  .kpis, .metabar {{ grid-template-columns: 1fr 1fr; }} .cols {{ grid-template-columns: 1fr; }}
  .content, .masthead, footer {{ padding-left: 16px; padding-right: 16px; }}
  table.grid {{ display: block; overflow-x: auto; }}
}}
@media print {{
  body {{ background: #fff; }} .toolbar {{ display: none; }}
  .page {{ margin: 0; border: 0; border-radius: 0; box-shadow: none; max-width: none; }}
  .pb {{ page-break-before: always; }}
}}
</style></head><body>

<div class="toolbar"><button onclick="window.print()">Print / Save as PDF</button></div>

<div class="page">
  <header class="masthead">
    <div class="brand">
      <div class="logo"><i>✉</i> SecureMailScope</div>
      <div class="class">{_e(meta.get('classification', 'CONFIDENTIAL'))}</div>
    </div>
    <h1>{_e(meta['title'])}</h1>
    <div class="subt">{_e(meta['analysis_type'])} · {_e(meta['tool'])}</div>
  </header>
  <div class="metabar">
    <div>Capture<b>{_e(ev['capture_ref'])}</b></div>
    <div>File<b>{_e(ev['filename'])}</b></div>
    <div>Traffic observed<b>{_e((ev['first_packet_at'] or '')[:19].replace('T', ' ')) or '—'} UTC</b></div>
    <div>Report generated<b>{_e(meta['generated_at'][:19].replace('T', ' '))} UTC</b></div>
  </div>
  <div class="content">{body}</div>
  <footer>
    <span>SecureMailScope · passive cryptographic posture assessment · {_e(meta['problem_statement'])}</span>
    <span>Deterministic: the same capture always produces the same findings and score. ML adds context, never verdicts.</span>
  </footer>
</div>
</body></html>"""
