export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";

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
  tls_pqc_offered: boolean;
  tls_pqc_selected: boolean;
  anomaly_score: number | null;
  is_anomalous: boolean;
  baseline_deviation_score: number | null;
}

export interface SessionDetail extends Session {
  state_transitions: { from: string; to: string; frame: number; timestamp: number; trigger: string }[] | null;
  events: { kind: string; frame: number; timestamp: number; direction: string; detail: string }[] | null;
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
