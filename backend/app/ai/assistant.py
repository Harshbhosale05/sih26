"""Ask the Analyst: natural-language questions answered from the evidence.

Two local models, no external service:

1. **Intent classifier.** TF-IDF over word and character n-grams feeding a
   logistic regression, trained at start-up on templated analyst questions
   (hundreds of paraphrases across 15 intents). Character n-grams make it
   tolerant of typos and abbreviations ("certs", "tls1.0", "pwd").
2. **Entity extraction.** Deterministic patterns for finding and session refs,
   IP addresses and ports, protocols, TLS versions, severities, topics and
   remediation actions.

The intent chooses a handler; the handler *computes* the answer from the
capture -- the same queries, scores and simulator the dashboard uses -- and
returns it with citations to the findings and sessions that support it. No
text is generated freely, so an answer can never state something the
evidence does not.
"""

from __future__ import annotations

from app.ml.runtime import native

import random
import re
from dataclasses import dataclass, field
from functools import lru_cache
from typing import Callable

# --------------------------------------------------------------------------- #
# Training data: templated analyst questions per intent
# --------------------------------------------------------------------------- #

_SLOTS = {
    "{sev}": ["critical", "high", "medium", "low", "severe", "serious"],
    "{tls}": ["TLS 1.0", "TLS 1.1", "TLS 1.2", "TLS 1.3", "tls1.0", "old TLS", "legacy TLS"],
    "{proto}": ["SMTP", "IMAP", "POP3", "mail", "email"],
    "{ip}": ["10.10.2.50", "10.10.2.51", "127.0.0.1", "192.168.1.10", "10.0.0.5:25"],
    "{fref}": ["F-0001", "F-0002", "F-0007", "finding 3"],
    "{sref}": ["SMTP-0001", "IMAP-0003", "POP3-0005", "SMTP-0024"],
    "{fix}": ["disable TLS 1.0", "enforce TLS", "require STARTTLS", "renew the certificate", "enable hybrid PQC",
              "deploy MTA-STS", "fix the ciphers", "turn on ML-KEM", "apply all fixes", "disable old TLS"],
}

_TEMPLATES: dict[str, list[str]] = {
    "summary": [
        "summarise this capture", "give me a summary", "what happened in this capture", "overview please",
        "brief me", "what is going on", "executive summary", "tl;dr", "what did you find", "summarize the assessment",
        "give me the big picture", "what's the situation", "describe this pcap", "what does this capture show",
        "quick summary of the traffic", "sum up the findings", "short report", "high level overview",
    ],
    "top_risks": [
        "what should I fix first", "top priorities", "what are the biggest risks", "most important issues",
        "where do I start", "what needs urgent attention", "rank the problems", "worst findings",
        "what is most dangerous", "biggest threats here", "priority list", "what to remediate first",
        "most critical problems", "which issues matter most", "show me the p1 items", "urgent issues",
    ],
    "posture_why": [
        "why is the score low", "explain the posture score", "how was the score calculated", "why is posture 71",
        "what brings the score down", "why not 100", "break down the score", "what limits the score",
        "explain the rating", "why is it action required", "how is the posture computed", "which dimension is weakest",
        "why did we get this score", "what affects the grade", "score explanation",
    ],
    "list_findings": [
        "show {sev} findings", "list all findings", "which findings are {sev}", "show me the {sev} issues",
        "list certificate findings", "what findings are there", "all failing findings", "findings on {ip}",
        "show findings about ciphers", "list the problems", "what issues were detected", "show {sev} problems",
        "findings related to starttls", "which rules fired", "list vulnerabilities", "show issues for {ip}",
    ],
    "list_sessions": [
        "show sessions using {tls}", "which sessions used {tls}", "list {proto} sessions", "sessions to {ip}",
        "show cleartext sessions", "which sessions were unencrypted", "list all sessions", "show high risk sessions",
        "sessions without forward secrecy", "which connections used {tls}", "show me {proto} connections",
        "unencrypted connections", "list sessions from {ip}", "show encrypted sessions", "sessions on port 25",
        "which sessions are risky", "show plaintext connections", "connections using weak ciphers",
    ],
    "credentials": [
        "were any passwords exposed", "did credentials leak", "show cleartext logins", "which accounts are compromised",
        "any plaintext auth", "were usernames sent in clear", "leaked credentials", "password exposure",
        "who logged in without tls", "auth login in cleartext", "credential leaks", "are passwords visible",
        "which users are affected", "exposed accounts", "pwd sent unencrypted",
    ],
    "pqc": [
        "are we quantum safe", "pqc readiness", "post quantum status", "is this ready for quantum computers",
        "harvest now decrypt later risk", "ml-kem usage", "quantum risk", "how quantum ready are we",
        "are clients offering pqc", "hybrid key exchange status", "when does this become decryptable",
        "mosca analysis", "quantum exposure", "is key exchange quantum resistant", "pqc migration status",
        "x25519mlkem768 support", "will quantum computers break this", "quantum threat",
        "how bad is the pqc situation", "how is our post quantum posture", "pqc status overview",
        "are we exposed to quantum attacks", "quantum readiness score",
    ],
    "certificates": [
        "certificate problems", "are any certs expired", "show certificate issues", "check the certificates",
        "which certificates are invalid", "cert chain status", "expired certificates", "self signed certs",
        "certificate validity", "tls certificate findings", "is the certificate trusted", "cert expiry",
        "hostname mismatch", "weak certificate keys", "sha1 certificates",
    ],
    "server_info": [
        "tell me about {ip}", "what is running on {ip}", "which servers were seen", "list the mail servers",
        "what software is the server", "server details for {ip}", "describe server {ip}", "what mail servers exist",
        "which server is worst", "show servers", "what does {ip} negotiate", "is {ip} postfix",
    ],
    "explain_finding": [
        "explain {fref}", "why was {fref} raised", "tell me about {fref}", "what does {fref} mean",
        "details of {fref}", "how to fix {fref}", "evidence for {fref}", "is {fref} real",
    ],
    "explain_session": [
        "what happened in {sref}", "explain session {sref}", "show {sref}", "why is {sref} risky",
        "details of {sref}", "walk me through {sref}", "trace {sref}", "is {sref} encrypted",
    ],
    "simulate_fix": [
        "what if we {fix}", "what happens if we {fix}", "simulate {fix}", "if I {fix} what changes",
        "impact of {fix}", "how much does the score improve if we {fix}", "project {fix}", "should we {fix}",
        "effect of {fix} on posture", "what would the score be after we {fix}", "{fix} what then",
    ],
    "attack_paths": [
        "how could an attacker exploit this", "attack paths", "what attacks are possible", "mitre att&ck mapping",
        "threat scenarios", "how would a hacker get in", "attack scenario", "what can an adversary do",
        "kill chain", "is there a man in the middle risk", "exploitation paths", "which techniques apply",
        "how bad could this get", "adversary view",
    ],
    "anomalies": [
        "any anomalies", "unusual sessions", "suspicious tls behaviour", "outliers", "anything strange",
        "anomalous handshakes", "unknown clients", "novel client fingerprints", "odd connections",
        "what looks abnormal", "deviations from baseline", "rare tls stacks", "suspicious clients",
    ],
    "help": [
        "help", "what can you do", "what can I ask", "how does this work", "examples", "commands",
        "who are you", "hello", "hi", "what questions can you answer",
    ],
}


def _expand(template: str, rng: random.Random, n: int) -> list[str]:
    slots = [s for s in _SLOTS if s in template]
    if not slots:
        return [template]
    out = set()
    for _ in range(n):
        t = template
        for s in slots:
            t = t.replace(s, rng.choice(_SLOTS[s]))
        out.add(t)
    return sorted(out)


_PREFIXES = ["", "", "can you ", "please ", "could you tell me ", "i want to know ", "hey, ", "quick question: ", "tell me "]
_SUFFIXES = ["", "", "?", " please", " in this capture", " for this pcap", " here"]


def _typo(text: str, rng: random.Random) -> str:
    """One realistic slip: dropped or swapped character in a longer word."""
    words = text.split()
    long_words = [i for i, w in enumerate(words) if len(w) > 5 and w.isalpha()]
    if not long_words:
        return text
    i = rng.choice(long_words)
    w = words[i]
    j = rng.randrange(1, len(w) - 2)
    words[i] = w[:j] + w[j + 1] + w[j] + w[j + 2:] if rng.random() < 0.5 else w[:j] + w[j + 1:]
    return " ".join(words)


def training_set() -> tuple[list[str], list[str]]:
    rng = random.Random(7)
    X, y = [], []
    for intent, templates in _TEMPLATES.items():
        for t in templates:
            for text in _expand(t, rng, 6):
                variants = {text}
                for _ in range(4):
                    v = rng.choice(_PREFIXES) + text + rng.choice(_SUFFIXES)
                    variants.add(_typo(v, rng) if rng.random() < 0.25 else v)
                for v in variants:
                    X.append(v)
                    y.append(intent)
    return X, y


def model():
    """Intent classifier and its card, trained once on the ML thread."""
    return native(_model)


@lru_cache(maxsize=1)
def _model():
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.linear_model import LogisticRegression
    from sklearn.model_selection import cross_val_score
    from sklearn.pipeline import FeatureUnion, Pipeline

    X, y = training_set()

    def make():
        return Pipeline([
            ("features", FeatureUnion([
                ("word", TfidfVectorizer(ngram_range=(1, 2), lowercase=True, sublinear_tf=True)),
                ("char", TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5), lowercase=True, sublinear_tf=True)),
            ])),
            ("clf", LogisticRegression(C=8.0, max_iter=2000)),
        ])

    cv = cross_val_score(make(), X, y, cv=5, scoring="accuracy")
    pipe = make().fit(X, y)
    card = {
        "algorithm": "TF-IDF (word 1-2 grams + character 3-5 grams) → logistic regression",
        "intents": sorted(set(y)),
        "training_examples": len(X),
        "cv_accuracy": round(float(cv.mean()), 3),
        "entities": ["finding refs", "session refs", "IP addresses / ports", "protocols", "TLS versions",
                     "severities", "topics", "remediation actions"],
    }
    return pipe, card


# --------------------------------------------------------------------------- #
# Entities
# --------------------------------------------------------------------------- #

_FIX_PATTERNS = [
    (r"\b(all|every|full plan|everything)\b.*\bfix|apply (all|everything)|full plan", "__all__"),
    (r"(ml-?kem|pqc|post.?quantum|quantum|hybrid)", "enable_hybrid_pqc"),
    (r"(mta.?sts|dane|tlsa|strip)", "deploy_mta_sts_dane"),
    (r"(tls ?(1\.0|1\.1|v?1(\.0)?\b)|legacy tls|old tls|deprecated)", "disable_legacy_tls"),
    (r"(cipher|forward secrecy|aead|cbc|rc4|3des)", "modern_ciphers"),
    (r"(renew|reissue|re-issue|new cert|certificate|cert\b)", "renew_certificate"),
    (r"(chain|intermediate)", "fix_certificate_chain"),
    (r"(dmarc)", "publish_dmarc"),
    (r"(port)", "standard_ports"),
    (r"(enforce|require|starttls|encrypt|tls only|auth only)", "enforce_tls"),
]

_TOPICS = {
    "certificate": r"cert|x\.?509|expir|self.?signed|hostname|chain|sha-?1",
    "cipher": r"cipher|cbc|rc4|3des|aead|forward secrecy|\bfs\b|pfs",
    "starttls": r"starttls|stls|strip|downgrade|upgrade",
    "credential": r"credential|password|passwd|pwd|login|auth|username|account",
    "cleartext": r"cleartext|plain.?text|unencrypted|not encrypted|in clear|no tls",
    "dns": r"mta.?sts|dane|dmarc|tls.?rpt|dns",
    "pqc": r"pqc|quantum|ml-?kem|kyber|hybrid",
    "risk": r"risky|high risk|critical risk|dangerous",
}

_TOPIC_CATEGORIES = {
    "certificate": lambda c: c.startswith("certificate_"),
    "cipher": lambda c: c in ("weak_cipher_suite", "no_forward_secrecy"),
    "starttls": lambda c: c.startswith("starttls_"),
    "credential": lambda c: c == "cleartext_credential_exposure",
    "cleartext": lambda c: c in ("cleartext_mail_transaction", "cleartext_credential_exposure", "starttls_not_advertised", "starttls_advertised_not_used"),
    "dns": lambda c: c.startswith(("mta_sts", "dane", "dmarc", "tlsrpt", "dns_")),
    "pqc": lambda c: c.startswith("pqc_"),
}


@dataclass
class Entities:
    findings: list[str] = field(default_factory=list)
    sessions: list[str] = field(default_factory=list)
    ips: list[str] = field(default_factory=list)
    ports: list[int] = field(default_factory=list)
    protocols: list[str] = field(default_factory=list)
    tls_versions: list[str] = field(default_factory=list)
    severities: list[str] = field(default_factory=list)
    topics: list[str] = field(default_factory=list)
    fixes: list[str] = field(default_factory=list)

    def serialise(self) -> dict:
        return {k: v for k, v in self.__dict__.items() if v}


def extract(text: str) -> Entities:
    t = text.lower()
    e = Entities()
    e.findings = sorted({f"F-{int(n):04d}" for n in re.findall(r"\bf-?(\d{1,4})\b", t)} | {f"F-{int(n):04d}" for n in re.findall(r"finding (\d{1,4})\b", t)})
    e.sessions = sorted({m.upper() for m in re.findall(r"\b(?:smtp|imap|pop3)-\d{4}\b", t)})
    for ip, port in re.findall(r"\b(\d{1,3}(?:\.\d{1,3}){3})(?::(\d{1,5}))?\b", t):
        e.ips.append(ip)
        if port:
            e.ports.append(int(port))
    e.ports += [int(p) for p in re.findall(r"\bport (\d{2,5})\b", t)]
    e.protocols = sorted({p.upper() for p in re.findall(r"\b(smtp|imap|pop3)\b(?!-\d)", t)})
    for pat, v in [(r"tls ?v?1\.0|tls ?1\b(?!\.)|tlsv1\b", "TLS 1.0"), (r"tls ?v?1\.1", "TLS 1.1"), (r"tls ?v?1\.2", "TLS 1.2"),
                   (r"tls ?v?1\.3", "TLS 1.3"), (r"ssl ?v?3", "SSL 3.0"), (r"legacy tls|old tls|deprecated", "__deprecated")]:
        if re.search(pat, t):
            e.tls_versions.append(v)
    sev_map = {"critical": "CRITICAL", "severe": "CRITICAL", "high": "HIGH", "serious": "HIGH", "medium": "MEDIUM", "low": "LOW", "info": "INFO"}
    e.severities = sorted({v for k, v in sev_map.items() if re.search(rf"\b{k}\b", t)})
    e.topics = [k for k, pat in _TOPICS.items() if re.search(pat, t)]
    for pat, fix in _FIX_PATTERNS:
        if re.search(pat, t) and fix not in e.fixes:
            e.fixes.append(fix)
            if fix == "__all__":
                break
    return e


# --------------------------------------------------------------------------- #
# Answers
# --------------------------------------------------------------------------- #

@dataclass
class Answer:
    intent: str
    text: list[str]
    table: dict | None = None
    citations: list[dict] = field(default_factory=list)
    actions: list[dict] = field(default_factory=list)
    followups: list[str] = field(default_factory=list)
    confidence: float = 0.0
    entities: dict = field(default_factory=dict)
    alternatives: list[dict] = field(default_factory=list)

    def serialise(self) -> dict:
        return self.__dict__


class Context:
    """Lazily computed views over one capture, shared by the handlers."""

    question: str = ""

    def __init__(self, capture, sessions, findings, providers: dict[str, Callable[[], object]]):
        self.capture = capture
        self.sessions = [s for s in sessions if s.protocol]
        self.findings = findings
        self._providers = providers
        self._cache: dict[str, object] = {}

    def get(self, key: str):
        if key not in self._cache:
            self._cache[key] = self._providers[key]()
        return self._cache[key]

    @property
    def by_ref(self):
        return {s.ref: s for s in self.sessions}


def ctx_question(ctx: "Context") -> str:
    return (ctx.question or "").lower()


def _srv(s) -> str:
    return f"{s.server_ip}:{s.server_port}"


def _cite_f(f) -> dict:
    return {"kind": "finding", "ref": f["ref"] if isinstance(f, dict) else f.ref,
            "label": f["title"] if isinstance(f, dict) else f.title}


def _cite_s(s) -> dict:
    return {"kind": "session", "ref": s.ref, "label": f"{s.client_ip} → {_srv(s)}"}


def _h_summary(ctx: Context, e: Entities) -> Answer:
    brief = ctx.get("brief")
    refs = sorted({r for s in brief["sentences"] for r in s["refs"]})
    return Answer(
        "summary",
        [s["text"] for s in brief["sentences"]],
        citations=[{"kind": "finding" if r.startswith("F-") else "session", "ref": r, "label": r} for r in refs],
        actions=[{"label": "Open overview", "to": ""}, {"label": "Open remediation", "to": "remediation"}],
        followups=["What should I fix first?", "How could an attacker exploit this?", "Are we quantum safe?"],
    )


def _h_top(ctx: Context, e: Entities) -> Answer:
    pr = [p for p in ctx.get("priorities") if p["verdict"] == "FAIL"][:5]
    if not pr:
        return Answer("top_risks", ["No findings in this capture require action."])
    rows = [[p["tier"], str(round(p["priority"])), p["severity"].title(), f"{p['ref']} · {p['title']}", p.get("session_ref") or "—"] for p in pr]
    top = pr[0]
    top_factors = ", ".join(f"{f['factor'].lower()} (+{f['points']:g})" for f in sorted(top["factors"], key=lambda x: -x["points"])[:3])
    return Answer(
        "top_risks",
        [f"Start with {top['ref']} ({top['title']}). It ranks first because of {top_factors}.",
         f"{len([p for p in pr if p['tier'] == 'P1'])} finding(s) are P1 (act now)."],
        table={"columns": ["Tier", "Priority", "Severity", "Finding", "Session"], "rows": rows},
        citations=[_cite_f(p) for p in pr],
        actions=[{"label": f"Open {top['ref']}", "to": f"findings/{top['ref']}"}],
        followups=[f"Explain {top['ref']}", "What if we apply all fixes?"],
    )


def _h_posture(ctx: Context, e: Entities) -> Answer:
    p = ctx.get("posture")
    dims = sorted([d for d in p["dimensions"] if d["score"] is not None], key=lambda d: d["score"])
    capped = [d for d in dims if any("Capped" in c for c in d["contributors"])]
    text = [f"The posture score is {p['overall']}/100, the weighted mean of {p['dimensions_assessed']} assessable dimensions."]
    if dims:
        w = dims[0]
        text.append(f"The weakest dimension is {w['label']} at {w['score']}: {'; '.join(w['contributors'][:2]) or w['detail']}.")
    if capped:
        text.append("Severe findings cap " + ", ".join(f"{d['label']} at {d['score']}" for d in capped)
                    + ", so the score reflects the worst observed condition rather than an average.")
    excluded = [d["label"] for d in p["dimensions"] if d["score"] is None]
    if excluded:
        text.append(f"Not assessed (no evidence): {', '.join(excluded)}.")
    rows = [[d["label"], "—" if d["score"] is None else str(d["score"]), f"{round(d['weight'] * 100)}%",
             "—" if d["coverage_pct"] is None else f"{round(d['coverage_pct'])}%"] for d in p["dimensions"]]
    return Answer("posture_why", text, table={"columns": ["Dimension", "Score", "Weight", "Coverage"], "rows": rows},
                  followups=["What should I fix first?", "What if we apply all fixes?"])


def _filter_findings(ctx: Context, e: Entities) -> list:
    out = [f for f in ctx.findings if f.verdict == "FAIL"] or list(ctx.findings)
    if e.severities:
        out = [f for f in out if f.severity in e.severities]
    topics = [t for t in e.topics if t in _TOPIC_CATEGORIES]
    if topics:
        out = [f for f in out if any(_TOPIC_CATEGORIES[t](f.category) for t in topics)]
    if e.ips:
        out = [f for f in out if any(ip in str(f.evidence or {}) or ip in f.description for ip in e.ips)]
    return sorted(out, key=lambda f: (f.severity_rank, f.ref))


def _h_findings(ctx: Context, e: Entities) -> Answer:
    fs = _filter_findings(ctx, e)
    desc = " ".join(filter(None, [", ".join(s.lower() for s in e.severities), ", ".join(t for t in e.topics if t in _TOPIC_CATEGORIES)]))
    if not fs:
        return Answer("list_findings", [f"No {desc + ' ' if desc else ''}findings in this capture."], followups=["List all findings"])
    rows = [[f.ref, f.severity.title(), f.title, f.session_ref or "—"] for f in fs[:25]]
    return Answer("list_findings", [f"{len(fs)} {desc + ' ' if desc else ''}finding{'s' if len(fs) != 1 else ''}."],
                  table={"columns": ["Ref", "Severity", "Finding", "Session"], "rows": rows},
                  citations=[_cite_f(f) for f in fs[:10]], actions=[{"label": "Open findings", "to": "findings"}],
                  followups=[f"Explain {fs[0].ref}"])


_CLEAR = {"PLAINTEXT_THROUGHOUT", "PLAINTEXT_AFTER_FAILURE", "STARTTLS_ADVERTISED_NOT_USED", "STARTTLS_NOT_ADVERTISED", "STARTTLS_REJECTED"}


def _h_sessions(ctx: Context, e: Entities) -> Answer:
    ss = list(ctx.sessions)
    crit = []
    noun = "session"
    if e.protocols:
        ss = [s for s in ss if s.protocol in e.protocols]
        noun = "/".join(e.protocols) + " session"
    versions = [v for v in e.tls_versions if not v.startswith("__")]
    if "__deprecated" in e.tls_versions:
        versions += ["TLS 1.0", "TLS 1.1", "SSL 3.0"]
    if versions:
        ss = [s for s in ss if s.tls_version in versions]
        crit.append("using " + ", ".join(sorted(set(versions))))
    if e.ips:
        ss = [s for s in ss if s.server_ip in e.ips or s.client_ip in e.ips]
        crit.append("involving " + ", ".join(e.ips))
    if e.ports:
        ss = [s for s in ss if s.server_port in e.ports]
        crit.append("on port " + ", ".join(map(str, e.ports)))
    if "cleartext" in e.topics or "credential" in e.topics:
        ss = [s for s in ss if s.encryption_state in _CLEAR]
        crit.append("in cleartext")
    if "cipher" in e.topics:
        ss = [s for s in ss if s.tls_forward_secrecy is False or s.tls_aead is False]
        crit.append("with weak ciphers or no forward secrecy")
    if "risk" in e.topics:
        ss = [s for s in ss if s.risk_class in ("high", "critical")]
        crit.append("classified high or critical risk")
    if "pqc" in e.topics:
        ss = [s for s in ss if s.tls_pqc_offered or s.tls_pqc_selected]
        crit.append("offering hybrid PQC")
    ss.sort(key=lambda s: -(s.risk_score or 0))
    label = " ".join(crit) or "in total"
    if not ss:
        return Answer("list_sessions", [f"No {noun}s {label}."], followups=["List all sessions"])
    rows = [[s.ref, f"{s.client_ip} → {_srv(s)}", s.encryption_state.replace("_", " ").lower(), s.tls_version or "—",
             (s.risk_class or "—").title()] for s in ss[:25]]
    return Answer("list_sessions", [f"{len(ss)} {noun}{'s' if len(ss) != 1 else ''} {label}."],
                  table={"columns": ["Session", "Connection", "Encryption", "TLS", "Risk"], "rows": rows},
                  citations=[_cite_s(s) for s in ss[:10]], actions=[{"label": "Open sessions", "to": "sessions"}],
                  followups=[f"What happened in {ss[0].ref}?"])


def _h_creds(ctx: Context, e: Entities) -> Answer:
    ss = [s for s in ctx.sessions if s.cleartext_auth_observed]
    if not ss:
        return Answer("credentials", ["No credentials were transmitted without encryption in this capture."])
    rows = []
    for s in ss:
        for ev in s.events or []:
            if ev.get("kind") == "auth_credential":
                m = ev.get("metadata") or {}
                rows.append([s.ref, _srv(s), m.get("mechanism", "—"), m.get("field", "—"), m.get("username_redacted") or "—",
                             f"#{ev.get('frame')}"])
    fs = [f for f in ctx.findings if f.category == "cleartext_credential_exposure"]
    return Answer(
        "credentials",
        [f"Yes. {len(ss)} session{'s' if len(ss) != 1 else ''} sent credentials before TLS was established: {', '.join(s.ref for s in ss)}.",
         "Usernames are shown redacted and passwords are never stored; only their length and a SHA-256 prefix are kept. Treat these accounts as compromised and reset them."],
        table={"columns": ["Session", "Server", "Mechanism", "Field", "User", "Frame"], "rows": rows},
        citations=[_cite_s(s) for s in ss] + [_cite_f(f) for f in fs],
        actions=[{"label": f"Open {fs[0].ref}", "to": f"findings/{fs[0].ref}"}] if fs else [],
        followups=["What if we enforce TLS?", "How could an attacker exploit this?"],
    )


def _h_pqc(ctx: Context, e: Entities) -> Answer:
    q = ctx.get("pqc")
    fc = ctx.get("forecast")
    median = next((r for r in fc["scenarios"] if r["key"] == "median"), None)
    text = [f"Post-quantum readiness is {q['score']}/100 ({q.get('level_label')}). {q.get('hndl_exposed_pct')}% of sessions use key exchange a future quantum computer could break."]
    offering = next((c for c in q["components"] if c["key"] == "client_capability"), None)
    selected = next((c for c in q["components"] if c["key"] == "pqc_key_exchange"), None)
    if offering and selected:
        text.append(f"{offering['observed']} of {offering['total']} clients offered a hybrid ML-KEM group; the server selected it in {selected['observed']}.")
    if median:
        text.append(f"Mosca's inequality (shelf life {fc['shelf_life_years']:g} y + migration {fc['migration_years']:g} y vs. a {median['year']} quantum computer): {median['mosca_verdict'].lower()}.")
    if q.get("actions"):
        text.append("Next step: " + q["actions"][0]["title"] + ".")
    rows = [[t["label"], str(t["sessions"]), f"{t['pct']}%", t["readable"]] for t in fc["tiers"]]
    return Answer("pqc", text, table={"columns": ["Key exchange", "Sessions", "Share", "Readable"], "rows": rows},
                  actions=[{"label": "Open Post-Quantum", "to": "pqc"}],
                  followups=["What if we enable hybrid PQC?", "Which sessions offer PQC?"])


def _h_certs(ctx: Context, e: Entities) -> Answer:
    fs = [f for f in ctx.findings if f.category.startswith("certificate_") and f.verdict == "FAIL"]
    observed = [s for s in ctx.sessions if s.cert_observable]
    text = [f"{len(observed)} of {sum(1 for s in ctx.sessions if s.tls_version)} TLS sessions presented an observable certificate (TLS 1.3 encrypts it)."]
    if fs:
        text.append(f"{len(fs)} certificate finding{'s' if len(fs) != 1 else ''}: " + "; ".join(f"{f.ref} {f.title.lower()}" for f in fs[:5]) + ".")
    elif observed:
        text.append("No validity, key, signature, hostname or chain problem was found in the observed certificates.")
    rows = []
    for s in observed[:20]:
        c = (s.tls_detail or {}).get("certificate") or {}
        leaf = (c.get("chain") or [{}])[0]
        rows.append([s.ref, leaf.get("subject_cn") or "—", (leaf.get("not_after") or "")[:10],
                     f"{leaf.get('public_key_algorithm')} {leaf.get('public_key_bits')}", (c.get("chain_trust") or "—").replace("_", " ").lower()])
    return Answer("certificates", text, table={"columns": ["Session", "Subject", "Expires", "Key", "Chain"], "rows": rows} if rows else None,
                  citations=[_cite_f(f) for f in fs[:6]], followups=["What if we renew the certificate?"])


def _h_servers(ctx: Context, e: Entities) -> Answer:
    sw = {s["server"]: s for s in ctx.get("software")}
    servers: dict[str, list] = {}
    for s in ctx.sessions:
        servers.setdefault(_srv(s), []).append(s)
    products = [w for w in ("postfix", "exim", "sendmail", "exchange", "dovecot", "courier", "cyrus", "zimbra") if w in ctx_question(ctx)]
    keys = [k for k in servers if not e.ips or k.split(":")[0] in e.ips]
    if products:
        keys = [k for k in keys if any(pr in (sw.get(k, {}).get("name", "").lower()) for pr in products)]
    if not keys:
        target = ", ".join(e.ips) or ", ".join(p.title() for p in products) or "that description"
        return Answer("server_info", [f"No mail server matching {target} was observed in this capture."])
    rows = []
    for k in keys:
        ss = servers[k]
        fs = [f for f in ctx.findings if f.verdict == "FAIL" and (k in str(f.evidence or {}) or any(f.session_ref == s.ref for s in ss))]
        worst = min((f.severity_rank for f in fs), default=None)
        rows.append([k, sw.get(k, {}).get("name", "—"), str(len(ss)),
                     ", ".join(sorted({s.tls_version for s in ss if s.tls_version})) or "none", str(len(fs)),
                     ["Critical", "High", "Medium", "Low", "Info"][worst] if worst is not None else "—"])
    ips = {k.split(":")[0] for k in keys}
    text = [f"{len(keys)} mail server endpoint{'s' if len(keys) != 1 else ''} observed"
            + (f" running {', '.join(p.title() for p in products)}" if products else "") + "."]
    if len(ips) == 1 and len(keys) > 1:
        ip = next(iter(ips))
        names = sorted({sw.get(k, {}).get("name", "unidentified") for k in keys})
        text = [f"{ip} exposes {len(keys)} mail service endpoints ({', '.join(k.split(':')[1] for k in sorted(keys, key=lambda x: int(x.split(':')[1])))}); software: {', '.join(names)}."]
    if len(keys) == 1:
        k = keys[0]
        info = sw.get(k)
        text = [f"{k} is {info['name'] if info else 'an unidentified server'}"
                + (f", identified from its banner \"{info['evidence']}\"" if info and info.get("confidence") == "banner" else "") + "."]
    return Answer("server_info", text, table={"columns": ["Server", "Software", "Sessions", "TLS", "Findings", "Worst"], "rows": rows},
                  followups=[f"Sessions to {keys[0].split(':')[0]}"])


def _h_explain_finding(ctx: Context, e: Entities) -> Answer:
    ref = e.findings[0] if e.findings else None
    f = next((x for x in ctx.findings if x.ref == ref), None)
    if f is None:
        return Answer("explain_finding", [f"I could not find {ref or 'that finding'} in this capture."], followups=["List all findings"])
    text = [f"{f.ref} — {f.title} ({f.severity.lower()}, verdict {f.verdict}).", f.description, f"Why: {f.rationale}"]
    if f.recommendation:
        text.append(f"Fix: {f.recommendation}")
    if f.evidence_frames:
        text.append(f"Evidence: frames {', '.join(map(str, f.evidence_frames[:6]))}" + (f" in {f.session_ref}." if f.session_ref else "."))
    return Answer("explain_finding", text, citations=[_cite_f(f)] + ([{"kind": "session", "ref": f.session_ref, "label": f.session_ref}] if f.session_ref else []),
                  actions=[{"label": f"Trace {f.ref}", "to": f"findings/{f.ref}"}], followups=[f"What if we fix {f.ref}?"])


def _h_explain_session(ctx: Context, e: Entities) -> Answer:
    ref = e.sessions[0] if e.sessions else None
    s = ctx.by_ref.get(ref or "")
    if s is None:
        return Answer("explain_session", [f"I could not find {ref or 'that session'} in this capture."], followups=["List all sessions"])
    path = " → ".join(t.get("to", "").replace("_", " ").lower() for t in (s.state_transitions or []))
    text = [f"{s.ref} is a {s.protocol} session from {s.client_ip} to {_srv(s)}; it ended {s.encryption_state.replace('_', ' ').lower()}."]
    if path:
        text.append(f"Encryption path: {path}.")
    if s.tls_version:
        text.append(f"Negotiated {s.tls_version} with {s.tls_cipher_suite}; forward secrecy {'yes' if s.tls_forward_secrecy else 'no'}; hybrid PQC {'yes' if s.tls_pqc_selected else 'no'}.")
    if s.cleartext_auth_observed:
        text.append("Credentials were sent before TLS was established.")
    rd = s.risk_detail or {}
    if rd:
        drivers = ", ".join(f"{d['label'].lower()} (+{d['impact']:.2f})" for d in rd.get("drivers", [])[:3]) or "no factor above its healthy baseline"
        text.append(f"The risk model classifies it {rd.get('risk_class')} ({round(rd.get('score', 0))}/100): {drivers}.")
    fs = [f for f in ctx.findings if f.session_ref == s.ref and f.verdict == "FAIL"]
    return Answer("explain_session", text, citations=[_cite_s(s)] + [_cite_f(f) for f in fs],
                  actions=[{"label": f"Open {s.ref}", "to": f"sessions/{s.ref}"}])


def _h_simulate(ctx: Context, e: Entities) -> Answer:
    plan = ctx.get("plan")
    if "__all__" in e.fixes:
        fixes = [{"id": st["fix_id"], "servers": st["servers"] or None} for st in plan["steps"]]
    else:
        fixes = [{"id": f, "servers": None} for f in e.fixes if not f.startswith("__")]
    if not fixes:
        return Answer("simulate_fix", ["Which change should I project? For example: disable TLS 1.0, enforce TLS, renew the certificate, deploy MTA-STS or enable hybrid PQC."],
                      followups=["What if we apply all fixes?", "What if we enable hybrid PQC?"])
    sim = ctx.get("simulate")(fixes)
    pb, pa = sim["posture"]["before"]["overall"], sim["posture"]["after"]["overall"]
    qb, qa = sim["pqc"]["before"]["score"], sim["pqc"]["after"]["score"]
    names = ", ".join(f["id"].replace("_", " ") for f in sim["fixes"])
    text = [f"Projection with {names}: posture {pb} → {pa}; failing findings {sim['findings']['before']} → {sim['findings']['after']}; "
            f"PQC readiness {qb} → {qa}."]
    if sim["risk"]["before"] and sim["risk"]["after"]:
        text.append(f"Risk index {round(sim['risk']['before']['index'])} → {round(sim['risk']['after']['index'])}; "
                    f"{len(sim['sessions_changed'])} session(s) would negotiate differently.")
    if sim["findings"]["remaining"]:
        text.append(f"{len(sim['findings']['remaining'])} finding(s) would remain, e.g. {sim['findings']['remaining'][0]['title'].lower()}.")
    elif sim["findings"]["resolved"]:
        text.append("All failing findings addressed by this change set would be resolved.")
    if pb == pa and qb == qa and not sim["findings"]["resolved"] and not sim["sessions_changed"]:
        why = {
            "enable_hybrid_pqc": "no client in this capture offered a hybrid ML-KEM group, so enabling it on the server changes nothing until clients are upgraded",
            "disable_legacy_tls": "no session in this capture negotiated TLS 1.0 or 1.1",
            "modern_ciphers": "no session negotiated a weak cipher suite",
            "renew_certificate": "no observed certificate has a validity, key, signature or name problem",
            "enforce_tls": "every session already negotiated TLS",
            "deploy_mta_sts_dane": "no STARTTLS stripping was observed",
        }
        reasons = [why[f["id"]] for f in sim["fixes"] if f["id"] in why]
        text.append("No observable effect on this capture: " + ("; ".join(reasons) if reasons else "none of the sessions would negotiate differently") + ".")
    rows = [[r["ref"] or "—", r["severity"].title(), r["title"], "Resolved"] for r in sim["findings"]["resolved"][:12]]
    rows += [[r["ref"] or "—", r["severity"].title(), r["title"], "Remains"] for r in sim["findings"]["remaining"][:8]]
    return Answer("simulate_fix", text, table={"columns": ["Ref", "Severity", "Finding", "After"], "rows": rows} if rows else None,
                  citations=[_cite_f(r) for r in sim["findings"]["resolved"][:8] if r["ref"]],
                  actions=[{"label": "Open remediation", "to": "remediation" + (f"?fix={fixes[0]['id']}" if len(fixes) == 1 else "")}])


def _h_attack(ctx: Context, e: Entities) -> Answer:
    a = ctx.get("attack")
    sc = a["scenarios"]
    if not sc:
        return Answer("attack_paths", ["No attack scenario is supported by the findings in this capture."])
    top = sc[0]
    steps = " → ".join(f"{st['stage']} ({', '.join(t['id'] for t in st['techniques'])})" for st in top["stages"])
    text = [f"The evidence is most consistent with \"{top['title']}\" — likelihood {round(top['likelihood'] * 100)}%, impact: {top['impact_label'].lower()}.",
            top["summary"], f"Path: {steps}."]
    rows = [[s["title"], s["level"], f"{round(s['likelihood'] * 100)}%", s["impact_label"], ", ".join(s["finding_refs"][:4]) or "—"] for s in sc]
    return Answer("attack_paths", text, table={"columns": ["Scenario", "Level", "Likelihood", "Impact", "Evidence"], "rows": rows},
                  citations=[{"kind": "finding", "ref": r, "label": r} for r in top["finding_refs"][:6]],
                  actions=[{"label": "Open AI Analyst", "to": "analyst"}],
                  followups=["What if we apply all fixes?"])


def _h_anomalies(ctx: Context, e: Entities) -> Answer:
    outliers = [s for s in ctx.sessions if s.is_anomalous]
    deviating = [s for s in ctx.sessions if s.baseline_deviations]
    fp = ctx.get("clusters")
    novel = [c for c in fp.get("clusters", []) if c.get("novel")]
    text = []
    text.append(f"Isolation Forest: {len(outliers)} outlier session(s)" + (f" ({', '.join(s.ref for s in outliers[:5])})." if outliers else "."))
    text.append(f"Server baselines: {len(deviating)} session(s) deviate from their server's usual parameters" + (f" ({', '.join(s.ref for s in deviating[:5])})." if deviating else "."))
    if fp.get("available"):
        text.append(f"Client fingerprints: {fp['cluster_count']} client stack cluster(s); {fp['novel_count']} handshake(s) from novel stacks.")
    text.append("These are deviations to review, not confirmed attacks.")
    rows = [[s.ref, _srv(s), f"{s.anomaly_score:.2f}" if s.anomaly_score is not None else "—",
             "; ".join(a.get("feature", "") for a in (s.anomaly_attribution or [])[:3]) or "—"] for s in outliers[:10]]
    rows += [[c["sessions"][0], ", ".join(c["servers"][:1]), "novel stack", c["ja4"]] for c in novel[:5]]
    return Answer("anomalies", text, table={"columns": ["Session", "Server", "Signal", "Detail"], "rows": rows} if rows else None,
                  citations=[_cite_s(s) for s in (outliers + deviating)[:8]],
                  actions=[{"label": "Open AI Analyst", "to": "analyst"}])


EXAMPLES = [
    "Summarise this capture", "What should I fix first?", "Were any passwords exposed?", "Are we quantum safe?",
    "What if we enable hybrid PQC?", "Show sessions using TLS 1.2", "How could an attacker exploit this?",
    "Explain F-0001", "Any unusual TLS behaviour?", "Why is the score low?",
]


def _h_help(ctx: Context, e: Entities) -> Answer:
    return Answer("help", ["I answer questions about this capture from its evidence: findings, sessions, certificates, PQC readiness, attack scenarios and anomalies, and I can project the effect of a change before you make it."],
                  followups=EXAMPLES[:6])


HANDLERS = {
    "summary": _h_summary, "top_risks": _h_top, "posture_why": _h_posture, "list_findings": _h_findings,
    "list_sessions": _h_sessions, "credentials": _h_creds, "pqc": _h_pqc, "certificates": _h_certs,
    "server_info": _h_servers, "explain_finding": _h_explain_finding, "explain_session": _h_explain_session,
    "simulate_fix": _h_simulate, "attack_paths": _h_attack, "anomalies": _h_anomalies, "help": _h_help,
}


def ask(ctx: Context, question: str) -> dict:
    pipe, _ = model()
    ctx.question = question
    e = extract(question)
    proba = native(pipe.predict_proba, [question])[0]
    classes = list(pipe.classes_)
    order = sorted(range(len(classes)), key=lambda i: -proba[i])
    intent, conf = classes[order[0]], float(proba[order[0]])

    # Explicit refs are unambiguous signals that override a weak classification.
    if e.findings and intent not in ("simulate_fix",) and conf < 0.6:
        intent = "explain_finding"
    elif e.sessions and intent not in ("simulate_fix",) and conf < 0.6:
        intent = "explain_session"
    if intent == "explain_finding" and not e.findings:
        intent = classes[order[1]]
    if intent == "explain_session" and not e.sessions:
        intent = classes[order[1]]

    # Topic keywords steer a weak classification toward the matching analysis.
    steer = {"pqc": "pqc", "certificate": "certificates", "credential": "credentials"}
    if conf < 0.5 and intent in ("summary", "help", "top_risks", "posture_why"):
        for topic, target in steer.items():
            if topic in e.topics:
                intent, conf = target, max(conf, 0.5)
                break

    if conf < 0.18:
        ans = Answer("help", ["I am not sure what you are asking. Try one of these:"], followups=EXAMPLES[:6])
    else:
        ans = HANDLERS.get(intent, _h_help)(ctx, e)
    ans.confidence = round(conf, 3)
    ans.entities = e.serialise()
    ans.alternatives = [{"intent": classes[i], "p": round(float(proba[i]), 3)} for i in order[1:3]]
    return ans.serialise()
