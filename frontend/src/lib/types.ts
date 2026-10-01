export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
export type RiskClass = "minimal" | "low" | "medium" | "high" | "critical";

export interface CaptureSummary {
  capture_id: string;
  ref: string;
  original_filename: string;
  sha256: string;
  size_bytes: number;
  packet_count: number | null;
  first_packet_at: string | null;
  last_packet_at: string | null;
  uploaded_at: string;
  status: "uploaded" | "validated" | "analyzing" | "complete" | "failed";
}

export interface CaptureList {
  total: number;
  items: CaptureSummary[];
}

export interface Overview {
  capture: {
    capture_id: string;
    ref: string;
    filename: string;
    sha256: string;
    packet_count: number | null;
    size_bytes: number;
    first_packet_at: string | null;
    last_packet_at: string | null;
    duration_seconds: number | null;
    snaplen_truncated: boolean;
    status: string;
  };
  sessions: {
    total: number;
    by_protocol: Record<string, number>;
    by_state: Record<string, number>;
    protected: number;
    cleartext: number;
    indeterminate: number;
  };
  findings: {
    total: number;
    by_severity: Record<string, number>;
    by_category: Record<string, number>;
    unknown_verdicts: number;
  };
  crypto: {
    by_tls_version: Record<string, number>;
    by_cipher: Record<string, number>;
    forward_secrecy: number;
    pqc_offered: number;
    pqc_selected: number;
  };
  coverage: {
    tls_sessions: number;
    certificate_observable: number;
    certificate_coverage_pct: number | null;
    sessions_fully_observed: number;
    session_coverage_pct: number | null;
    note: string;
  };
}

export interface Dimension {
  key: string;
  label: string;
  score: number | null;
  status: string;
  assessed: number;
  total: number;
  coverage_pct: number | null;
  weight: number;
  standard: string;
  detail: string;
  contributors: string[];
}

export interface PqcReadiness {
  score: number | null;
  level: string | null;
  level_label: string | null;
  components: {
    key: string;
    label: string;
    weight: number;
    score: number | null;
    observed: number;
    total: number;
    assessed: boolean;
  }[];
  formula: string;
  cap_note: string | null;
  exposure: {
    tier: string;
    label: string;
    risk: string;
    explanation: string;
    sessions: number;
    pct: number;
  }[];
  hndl_exposed_sessions: number;
  hndl_exposed_pct: number | null;
  servers: {
    server: string;
    sessions: number;
    worst_tier: string | null;
    tiers: Record<string, number>;
    pqc_selected: number;
    clients_offering_pqc: number;
    tls13: number;
    dominant_group: string | null;
    migration_gap: boolean;
  }[];
  actions: { priority: number; title: string; detail: string }[];
  framing: string;
  standards: string[];
  groups?: { group: string; pqc: boolean; offered: number; offered_pct: number; selected: number; selected_pct: number }[];
  tls_versions?: Record<string, number>;
}

export interface PostureResponse {
  posture: {
    overall: number | null;
    dimensions: Dimension[];
    assessed_weight: number;
    dimensions_assessed: number;
    dimensions_total: number;
    note: string;
    calculation: {
      formula: string;
      terms: { dimension: string; score: number; weight: number; product: number }[];
      numerator: number;
      denominator: number;
      result: number | null;
      rounded: number | null;
      excluded: { dimension: string; reason: string; weight: number }[];
      coverage_meaning: string;
    };
  };
  pqc_readiness: PqcReadiness;
  fingerprints: {
    server: string;
    sessions: number;
    protocols: Record<string, number>;
    banner: string | null;
    has_baseline: boolean;
    median_handshake_ms: number | null;
    dimensions: Record<string, { name: string; values: { value: string; count: number; share: number }[] }>;
  }[];
  deviations: {
    session_ref: string;
    server: string;
    score: number | null;
    deviations: { label: string; expected: string; observed: string; expected_share: number }[];
    anomaly_score: number | null;
    is_anomalous: boolean;
    attribution: { feature: string; contribution?: number; value?: number }[];
  }[];
  anomaly: {
    available: boolean;
    reason: string | null;
    model: string | null;
    sessions_scored: number;
    outliers: number;
    disclaimer: string;
  };
}

export interface Finding {
  ref: string;
  category: string;
  severity: Severity;
  verdict: "PASS" | "FAIL" | "UNKNOWN";
  confidence: number;
  detection_method: string;
  title: string;
  description: string;
  rationale: string;
  recommendation: string | null;
  standard_refs: string[] | null;
  session_ref: string | null;
  evidence: Record<string, unknown> | null;
  evidence_frames: number[] | null;
  wireshark_filter: string | null;
  affected_sessions: number;
}

export interface BlastRadius {
  kind: "finding" | "crypto";
  key: string;
  node: string;
  title: string;
  severity: Severity;
  finding_refs: string[];
  domains: string[];
  direct_sessions: number;
  direct_session_refs: string[];
  direct_pct: number;
  dependent_sessions: number;
  dependent_pct: number;
  servers: string[];
  servers_pct: number;
  dependent_clients: number;
  clients_pct: number;
  credentials_exposed: number;
  protocols: Record<string, number>;
  blast_score: number;
}

export interface Explanation {
  finding: {
    ref: string;
    title: string;
    category: string;
    severity: Severity;
    verdict: string;
    confidence: number;
    detection_method: string;
    description: string;
    recommendation: string | null;
    standard_refs: string[];
    session_ref: string | null;
    affected_sessions: number;
  };
  chain: { kind: string; title: string; text: string }[];
  observations: { frame: number; direction: string | null; kind: string; detail: string }[];
  facts: { key: string; label: string; value: unknown }[];
  confidence_factors: { factor: string; value: unknown; note?: string }[];
  limits: string[];
  ml_context: {
    anomaly_score: number | null;
    is_anomalous: boolean;
    attribution: { feature: string; contribution?: number; value?: number }[];
    baseline_deviation_score: number | null;
    baseline_deviations: { label: string; expected: string; observed: string }[];
    role: string;
  } | null;
  posture_impact: { dimension: string; ceiling: number; text: string }[];
  blast_radius: BlastRadius | null;
  verification: {
    wireshark_filter: string | null;
    evidence_frames: number[];
    pcap_url: string;
    capture_sha256: string;
    capture_ref: string;
    how: string;
  };
}

export interface Session {
  session_id: string;
  ref: string;
  protocol: string | null;
  client_ip: string;
  client_port: number;
  server_ip: string;
  server_port: number;
  server_banner: string | null;
  encryption_state: string;
  tls_established: boolean;
  upgrade_advertised: boolean;
  upgrade_requested: boolean;
  cleartext_auth_observed: boolean;
  is_indeterminate: boolean;
  first_frame: number;
  last_frame: number;
  wireshark_filter: string;
  tls_version: string | null;
  tls_cipher_suite: string | null;
  tls_selected_group: string | null;
  tls_sni: string | null;
  tls_ja4: string | null;
  tls_ja4s: string | null;
  tls_forward_secrecy: boolean | null;
  tls_aead: boolean | null;
  tls_pqc_offered: boolean;
  tls_pqc_selected: boolean;
  cert_observable: boolean;
  anomaly_score: number | null;
  is_anomalous: boolean;
  baseline_deviation_score: number | null;
  risk_class: RiskClass | null;
  risk_score: number | null;
  risk_confidence: number | null;
  start_time: number | null;
  end_time: number | null;
  stream_index: number | null;
}

export interface ProtocolEvent {
  kind: string;
  frame: number;
  timestamp: number;
  direction: "c2s" | "s2c" | string;
  detail: string;
  metadata?: Record<string, unknown>;
}

export interface StateTransition {
  from: string;
  to: string;
  frame: number;
  timestamp: number;
  trigger: string;
}

export interface CertLeaf {
  index: number;
  subject: string;
  subject_cn: string | null;
  issuer: string;
  issuer_cn: string | null;
  serial: string;
  not_before: string;
  not_after: string;
  public_key_algorithm: string;
  public_key_bits: number | null;
  signature_algorithm: string;
  san: string[];
  is_ca: boolean;
  fingerprint_sha256: string;
}

export interface CertificateDetail {
  observed: boolean;
  chain_length: number;
  chain: CertLeaf[];
  expired: boolean;
  not_yet_valid: boolean;
  days_to_expiry: number | null;
  expiring_soon: boolean;
  hostname_match: boolean | null;
  checked_hostname: string | null;
  weak_key: boolean;
  broken_signature: boolean;
  self_signed: boolean;
  chain_incomplete: boolean;
  chain_invalid?: boolean;
  chain_trust: string;
  chain_trust_reason: string;
  chain_links?: { child: number; issuer: number | "trust_store"; status: string; problems: string[] }[];
  chain_anchor?: { subject: string; source: string; fingerprint_sha256: string; presented: boolean } | null;
  evaluated_at: string | null;
  reasons: string[];
}

export interface TlsDetail {
  observed?: boolean;
  sni?: string | null;
  alpn?: string | null;
  ja3?: string | null;
  ja3s?: string | null;
  ja4?: string | null;
  ja4s?: string | null;
  versions_offered?: string[];
  negotiated_version?: string | null;
  groups_offered?: string[];
  selected_group?: string | null;
  pqc_groups_offered?: string[];
  pqc_group_selected?: string | null;
  handshake_duration_ms?: number | null;
  cipher_suite?: {
    code: string;
    name: string;
    key_exchange: string | null;
    authentication: string | null;
    encryption: string | null;
    key_size: number | null;
    mode: string | null;
    mac_hash: string | null;
    forward_secrecy: boolean | null;
    aead: boolean;
    weaknesses: string[];
  } | null;
  certificate?: CertificateDetail | null;
  cert_unobservable_reason?: string | null;
}

export interface RiskDriver {
  feature: string;
  label: string;
  detail?: string;
  features?: string[];
  impact: number;
}

export interface RiskDetail {
  session_ref: string;
  risk_class: RiskClass;
  confidence: number;
  score: number;
  probabilities: Record<string, number>;
  drivers: RiskDriver[];
  baseline_severity: number | null;
  baseline_class: RiskClass | null;
}

export interface SessionDetail extends Session {
  detection_method: string;
  upgrade_advertised_mangled: boolean;
  has_gaps: boolean;
  session_complete: boolean;
  tls_key_exchange: string | null;
  tls_ja3: string | null;
  cert_unobservable_reason: string | null;
  baseline_deviations: { label: string; expected: string; observed: string }[] | null;
  anomaly_attribution: { feature: string; value?: number; population_median?: number; deviation_mad?: number }[] | null;
  state_transitions: StateTransition[] | null;
  events: ProtocolEvent[] | null;
  tls_detail: TlsDetail | null;
  risk_detail: RiskDetail | null;
}

export interface StarttlsAnalytics {
  summary: {
    email_sessions: number;
    starttls_eligible: number;
    observable: number;
    unobservable: number;
    implicit_tls: number;
    upgraded: number;
    adoption_pct: number | null;
    cleartext_fallbacks: number;
    stripped: number;
  };
  funnel: { stage: string; label: string; count: number; pct_of_start: number | null; drop_from_previous: number }[];
  failure_points: {
    key: string;
    label: string;
    owner: string | null;
    severity: string;
    explanation: string;
    count: number;
    pct: number;
    servers: string[];
    cleartext_fallbacks: number;
    examples: { session_ref: string; server: string; evidence_frame: number | null }[];
  }[];
  servers: {
    key: string;
    sessions: number;
    observable: number;
    adoption_pct: number | null;
    advertise_pct: number | null;
    failure_points: Record<string, number>;
    dominant_failure: string | null;
    cleartext_fallbacks: number;
    implicit_tls_sessions: number;
  }[];
  protocols: { key: string; sessions: number; adoption_pct: number | null; observable: number }[];
  timeline: {
    bucket: number;
    offset_seconds: number;
    attempts: number;
    upgraded: number;
    failed: number;
    unobservable: number;
    adoption_pct: number | null;
  }[];
  method: string;
}

export interface GraphNode {
  id: string;
  type: "client" | "server" | "crypto" | "weakness" | "domain";
  label: string;
  risk: string;
  sub: string | null;
  metrics: Record<string, unknown>;
}

export interface GraphData {
  nodes: GraphNode[];
  edges: { source: string; target: string; type: string; weight: number; cleartext?: number }[];
  blast_radius: BlastRadius[];
  servers: { server: string; node: string; clients: number; sessions: number; cleartext: number; risk: string; weaknesses: string[] }[];
  totals: { sessions: number; clients: number; servers: number; weaknesses: number; client_nodes_aggregated: number };
  method: string;
}

export interface DriftMetricDef {
  key: string;
  label: string;
  unit: string;
  better: string;
}

export interface DriftTimeline {
  metrics: DriftMetricDef[];
  points: {
    capture_id: string;
    ref: string;
    filename: string;
    observed_at: string | null;
    sessions: number;
    servers: number;
    metrics: Record<string, number | null>;
  }[];
  steps: { from: string; to: string; verdict: string; regressions: number; improvements: number; neutral_changes: number }[];
}

export interface DriftCompare {
  baseline: { capture_id: string; ref: string; filename: string; observed_at: string | null; sessions: number };
  current: { capture_id: string; ref: string; filename: string; observed_at: string | null; sessions: number };
  summary: {
    verdict: string;
    regressions: number;
    improvements: number;
    neutral_changes: number;
    servers_compared: number;
    servers_added: number;
    servers_removed: number;
  };
  metrics: (DriftMetricDef & { baseline: number | null; current: number | null; delta: number | null; direction: string })[];
  servers: {
    server: string;
    status: string;
    changes: { dimension: string; label: string; from: string; to: string; direction: string }[];
  }[];
  findings: { category: string; title: string; severity: Severity; status: string; baseline_count: number; current_count: number }[];
  method: string;
}


// ---------------------------------------------------------------------------
// Intelligence, remediation and simulation
// ---------------------------------------------------------------------------

export interface RiskIndex {
  index: number;
  mean_score: number;
  tail_score: number;
  distribution: Record<RiskClass, number>;
  sessions: number;
  formula: string;
}

export interface ModelCard {
  available: boolean;
  reason?: string;
  name?: string;
  version?: string;
  algorithm?: string;
  sklearn_version?: string;
  classes?: RiskClass[];
  features?: number;
  training_rows?: number;
  class_counts?: Record<string, number>;
  labelling?: string;
  evaluation?: {
    cv_macro_f1_mean: number;
    cv_macro_f1_std: number;
    cv_folds: number;
    holdout_rows: number;
    holdout_accuracy: number;
    holdout_macro_f1: number;
    per_class: Record<string, { precision: number; recall: number; "f1-score": number; support: number }>;
    confusion_matrix: { labels: string[]; matrix: number[][] };
  };
  feature_importance?: { feature: string; label: string; gain_importance: number; permutation_importance: number }[];
  explanation_method?: string;
  limitations?: string[];
}

export interface RiskResponse {
  index: RiskIndex | null;
  sessions: (RiskDetail & {
    ref: string;
    protocol: string;
    server: string;
    client: string;
    encryption_state: string;
    tls_version: string | null;
  })[];
  unclassified: number;
  model: ModelCard;
}

export interface PriorityFactor {
  factor: string;
  points: number;
  detail: string;
  source: string;
}

export interface Priority {
  rank: number;
  ref: string;
  category: string;
  title: string;
  severity: Severity;
  verdict: "PASS" | "FAIL" | "UNKNOWN";
  session_ref: string | null;
  priority: number;
  tier: "P1" | "P2" | "P3" | "P4";
  tier_label: string;
  factors: PriorityFactor[];
}

export interface Software {
  key: string;
  name: string;
  family: string;
  version: string | null;
  evidence: string;
  confidence: string;
  server: string;
  hostname: string;
  port: number;
  protocol: string;
}

export interface SnippetLine {
  op: "+" | "-" | " ";
  text: string;
}

export interface Playbook {
  id: string;
  title: string;
  summary: string;
  owner: string;
  effort: number;
  effort_label: string;
  group: string;
  standards: string[];
  rationale: string;
  resolves: string[];
  software: { key: string; name: string | null; version: string | null; evidence: string | null; specific: boolean };
  target: { server: string | null; host: string; port: number; domain: string };
  snippets: { file: string; lang: string; lines: SnippetLine[]; apply: string[]; note: string | null }[];
  verify: string[];
  expected_outcome: string;
  caution: string | null;
}

export interface PlanStep {
  step: number;
  fix_id: string;
  title: string;
  group: string;
  owner: string;
  effort: number;
  servers: string[];
  software: { server: string; name: string; version: string | null }[];
  addresses: { ref: string; category: string; severity: Severity; title: string }[];
  score_before: number | null;
  score_after: number | null;
  score_gain: number;
  findings_after: number;
  severity_after: Record<string, number>;
  risk_points_removed: number;
  playbook: Playbook;
}

export interface RemediationPlan {
  baseline: { score: number | null; findings: number; severity: Record<string, number> };
  target: { score: number | null; findings: number };
  steps: PlanStep[];
  servers: Software[];
  evidence_gaps: { category: string; action: string; findings: string[] }[];
  method: string;
}

export interface SessionView {
  encryption_state: string;
  tls_version: string | null;
  cipher_suite: string | null;
  forward_secrecy: boolean | null;
  pqc_selected: boolean;
  cleartext_auth: boolean;
  certificate_ok: boolean | null;
  risk_class: RiskClass | null;
  risk_score: number | null;
}

export interface FindingRow {
  ref: string | null;
  category: string;
  severity: Severity;
  title: string;
  session_ref: string | null;
  verdict: string;
}

export interface StateSummary {
  sessions: number;
  protected: number;
  cleartext: number;
  credentials_exposed: number;
  by_state: Record<string, number>;
  by_tls_version: Record<string, number>;
  forward_secrecy: number;
  pqc_selected: number;
}

export interface PqcView {
  score: number | null;
  level_label: string | null;
  hndl_exposed_pct: number | null;
  exposure: { tier: string; label: string; sessions: number; pct: number }[];
}

export interface Simulation {
  fixes: { id: string; servers: string[] | null }[];
  projection: true;
  posture: { before: PostureResponse["posture"]; after: PostureResponse["posture"] };
  risk: { before: RiskIndex | null; after: RiskIndex | null };
  pqc: { before: PqcView; after: PqcView };
  state: { before: StateSummary; after: StateSummary };
  findings: {
    before: number;
    after: number;
    resolved: FindingRow[];
    remaining: FindingRow[];
    introduced: FindingRow[];
    by_severity_before: Record<string, number>;
    by_severity_after: Record<string, number>;
  };
  sessions_changed: {
    ref: string;
    server: string;
    protocol: string;
    fixes: string[];
    tls_profile_source: string | null;
    before: SessionView;
    after: SessionView;
  }[];
  graph: { before: GraphData; after: GraphData } | null;
  note: string;
  fixed_this_finding?: boolean;
  applied_fixes?: string[];
}

export interface Trace {
  capture: { id: string; ref: string; filename: string; sha256: string; packets: number | null };
  finding: Explanation["finding"];
  explanation: Explanation;
  session: {
    ref: string;
    protocol: string;
    stream_index: number;
    client: string;
    server: string;
    first_frame: number;
    last_frame: number;
    encryption_state: string;
    state_transitions: StateTransition[];
    events: ProtocolEvent[];
    tls_version: string | null;
    tls_cipher_suite: string | null;
    risk: RiskDetail | null;
    wireshark_filter: string;
  } | null;
  priority: Priority | null;
  software: Software | null;
  scope: string[];
  fixes: Playbook[];
  evidence_action: string | null;
  projection: Simulation | null;
}

export interface FixCatalogueEntry {
  id: string;
  title: string;
  summary: string;
  resolves: string[];
  owner: string;
  effort: number;
  group: string;
  standards: string[];
  software: string[];
}

export interface CaptureDetail extends CaptureSummary {
  container_format: string | null;
  duration_seconds: number | null;
  snaplen: number | null;
  snaplen_truncated: boolean;
  error_message: string | null;
}

// ---------------------------------------------------------------------------
// AI-assisted analysis
// ---------------------------------------------------------------------------

export interface Brief {
  sentences: { text: string; refs: string[]; kind: "fact" | "assessment" | "risk" | "pqc" | "anomaly" | "action" }[];
  actions: { title: string; fix_id: string; servers: string[]; score_after: number | null; addresses: string[] }[];
}

export interface AskAnswer {
  intent: string;
  text: string[];
  table: { columns: string[]; rows: string[][] } | null;
  citations: { kind: "finding" | "session" | "server"; ref: string; label: string }[];
  actions: { label: string; to: string }[];
  followups: string[];
  confidence: number;
  entities: Record<string, unknown>;
  alternatives: { intent: string; p: number }[];
}

export interface AttackScenario {
  key: string;
  title: string;
  summary: string;
  likelihood: number;
  impact: number;
  impact_label: string;
  exposure_pct: number;
  score: number;
  level: "High" | "Elevated" | "Low";
  indicators: { label: string; weight: number; observed: boolean; required: boolean; findings: string[]; contribution: number }[];
  stages: { stage: string; description: string; techniques: { id: string; name: string; url: string }[] }[];
  finding_refs: string[];
  sessions: string[];
  servers: string[];
  mitigations: string[];
}

export interface AttackPaths {
  scenarios: AttackScenario[];
  techniques: { id: string; name: string; url: string }[];
  method: string;
}

export interface FingerprintClusters {
  available: boolean;
  reason?: string;
  sessions?: number;
  cluster_count?: number;
  novel_count?: number;
  clusters: {
    id: string;
    size: number;
    share_pct: number;
    novel: boolean;
    ja4: string;
    ja3: string | null;
    clients: string[];
    servers: string[];
    sessions: string[];
    profile: { max_version: string | null; offers_pqc: boolean; cipher_count: number; extension_count: number; groups: string[] };
  }[];
  points: { ref: string; x: number; y: number; cluster: string; client: string; ja4: string; novel: boolean }[];
  features: string[];
  method?: string;
}

export interface QuantumForecast {
  shelf_life_years: number;
  captured_year: number;
  confidential_until: number;
  migration_years: number;
  migration_steps: { step: string; years: number }[];
  tiers: { tier: string; label: string; sessions: number; pct: number; readable: string }[];
  scenarios: {
    key: string;
    label: string;
    year: number;
    basis: string;
    years_from_today: number;
    x_plus_y: number;
    mosca_verdict: "Act now" | "Within margin";
    mosca_margin_years: number;
    captured_traffic_at_risk: boolean;
    exposed_sessions: number;
    exposed_pct: number;
    years_of_exposure: number;
  }[];
  summary: string;
  method: string;
  sources: string[];
}

export interface AssistantCard {
  algorithm: string;
  intents: string[];
  training_examples: number;
  cv_accuracy: number;
  entities: string[];
  examples: string[];
}
