import { QueryClient, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import type {
  CaptureDetail,
  CaptureList,
  DriftCompare,
  DriftTimeline,
  Finding,
  FixCatalogueEntry,
  GraphData,
  ModelCard,
  Overview,
  PostureResponse,
  Priority,
  RemediationPlan,
  RiskResponse,
  Session,
  SessionDetail,
  Simulation,
  Software,
  StarttlsAnalytics,
  Trace,
} from "./types";

export class ApiError extends Error {
  constructor(public status: number, message: string) {
    super(message);
  }
}

async function parse<T>(res: Response): Promise<T> {
  if (!res.ok) {
    let message = `${res.status} ${res.statusText}`;
    try {
      const body = await res.json();
      if (body?.detail) message = typeof body.detail === "string" ? body.detail : JSON.stringify(body.detail);
    } catch {
      /* non-JSON error body */
    }
    throw new ApiError(res.status, message);
  }
  return res.json() as Promise<T>;
}

export const api = {
  get: <T,>(path: string) => fetch(path).then((r) => parse<T>(r)),
  post: <T,>(path: string, body?: unknown) =>
    fetch(path, {
      method: "POST",
      headers: body === undefined ? undefined : { "content-type": "application/json" },
      body: body === undefined ? undefined : JSON.stringify(body),
    }).then((r) => parse<T>(r)),

  /** Upload with progress. fetch() has no upload progress, so XHR it is. */
  upload<T>(path: string, file: File, onProgress: (pct: number) => void): Promise<T> {
    return new Promise((resolve, reject) => {
      const xhr = new XMLHttpRequest();
      const form = new FormData();
      form.append("file", file);
      xhr.open("POST", path);
      xhr.upload.onprogress = (e) => e.lengthComputable && onProgress(Math.round((100 * e.loaded) / e.total));
      xhr.onload = () => {
        let body: { detail?: string } | null = null;
        try {
          body = xhr.responseText ? JSON.parse(xhr.responseText) : null;
        } catch {
          body = null;
        }
        if (xhr.status >= 200 && xhr.status < 300) resolve(body as T);
        else reject(new ApiError(xhr.status, body?.detail ?? xhr.statusText));
      };
      xhr.onerror = () => reject(new ApiError(0, "Network error"));
      xhr.send(form);
    });
  },
};

export const queryClient = new QueryClient({
  defaultOptions: {
    queries: { staleTime: 30_000, refetchOnWindowFocus: false, retry: 1 },
  },
});

const base = (id: string) => `/api/captures/${id}`;

// --------------------------------------------------------------------------- queries

export const useCaptures = () =>
  useQuery({
    queryKey: ["captures"],
    queryFn: () => api.get<CaptureList>("/api/captures?limit=200"),
    refetchInterval: (q) =>
      q.state.data?.items.some((c) => c.status === "analyzing" || c.status === "uploaded") ? 2000 : false,
  });

export const useCapture = (id?: string) =>
  useQuery({ queryKey: ["capture", id], queryFn: () => api.get<CaptureDetail>(base(id!)), enabled: !!id });

export const useOverview = (id?: string) =>
  useQuery({ queryKey: ["overview", id], queryFn: () => api.get<Overview>(`${base(id!)}/overview`), enabled: !!id });

export const usePosture = (id?: string) =>
  useQuery({ queryKey: ["posture", id], queryFn: () => api.get<PostureResponse>(`${base(id!)}/posture`), enabled: !!id });

export const useFindings = (id?: string) =>
  useQuery({ queryKey: ["findings", id], queryFn: () => api.get<Finding[]>(`${base(id!)}/findings`), enabled: !!id });

export const usePriorities = (id?: string) =>
  useQuery({ queryKey: ["priorities", id], queryFn: () => api.get<Priority[]>(`${base(id!)}/priorities`), enabled: !!id });

export const useSessions = (id?: string) =>
  useQuery({ queryKey: ["sessions", id], queryFn: () => api.get<Session[]>(`${base(id!)}/sessions`), enabled: !!id });

export const useSession = (id?: string, ref?: string) =>
  useQuery({
    queryKey: ["session", id, ref],
    queryFn: () => api.get<SessionDetail>(`${base(id!)}/sessions/${ref}`),
    enabled: !!id && !!ref,
  });

export const useGraph = (id?: string) =>
  useQuery({ queryKey: ["graph", id], queryFn: () => api.get<GraphData>(`${base(id!)}/graph`), enabled: !!id });

export const useRisk = (id?: string) =>
  useQuery({ queryKey: ["risk", id], queryFn: () => api.get<RiskResponse>(`${base(id!)}/risk`), enabled: !!id });

export const useStarttls = (id?: string) =>
  useQuery({ queryKey: ["starttls", id], queryFn: () => api.get<StarttlsAnalytics>(`${base(id!)}/starttls`), enabled: !!id });

export const useTrace = (id?: string, ref?: string) =>
  useQuery({
    queryKey: ["trace", id, ref],
    queryFn: () => api.get<Trace>(`${base(id!)}/findings/${ref}/trace`),
    enabled: !!id && !!ref,
  });

export const usePlan = (id?: string) =>
  useQuery({ queryKey: ["plan", id], queryFn: () => api.get<RemediationPlan>(`${base(id!)}/remediation`), enabled: !!id });

export const useSoftware = (id?: string) =>
  useQuery({ queryKey: ["software", id], queryFn: () => api.get<Software[]>(`${base(id!)}/software`), enabled: !!id });

export const useSimulation = (id: string | undefined, fixes: { id: string; servers: string[] | null }[]) =>
  useQuery({
    queryKey: ["simulate", id, fixes],
    queryFn: () => api.post<Simulation>(`${base(id!)}/simulate`, { fixes }),
    enabled: !!id,
    placeholderData: (prev) => prev,
  });

export const useModelCard = () =>
  useQuery({ queryKey: ["model-card"], queryFn: () => api.get<ModelCard>("/api/models/risk") });

export const useFixCatalogue = () =>
  useQuery({ queryKey: ["fix-catalogue"], queryFn: () => api.get<FixCatalogueEntry[]>("/api/models/fixes") });

export const useDriftTimeline = () =>
  useQuery({ queryKey: ["drift-timeline"], queryFn: () => api.get<DriftTimeline>("/api/drift/timeline") });

export const useDriftCompare = (baseline?: string, current?: string) =>
  useQuery({
    queryKey: ["drift-compare", baseline, current],
    queryFn: () => api.get<DriftCompare>(`/api/drift/compare?baseline=${baseline}&current=${current}`),
    enabled: !!baseline && !!current && baseline !== current,
  });

// --------------------------------------------------------------------------- mutations

export function useAnalyze() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => api.post(`${base(id)}/analyze`),
    onSuccess: (_d, id) => {
      qc.invalidateQueries({ queryKey: ["captures"] });
      for (const key of ["capture", "overview", "posture", "findings", "priorities", "sessions", "graph", "risk", "starttls", "plan", "software"]) {
        qc.invalidateQueries({ queryKey: [key, id] });
      }
      qc.invalidateQueries({ queryKey: ["drift-timeline"] });
    },
  });
}

export const exportUrl = (id: string, kind: "report.json" | "report.html" | "report.pdf" | "cbom") => `${base(id)}/${kind}`;
export const sessionPcapUrl = (id: string, ref: string) => `${base(id)}/sessions/${ref}/pcap`;
export const findingPcapUrl = (id: string, ref: string) => `${base(id)}/findings/${ref}/pcap`;
