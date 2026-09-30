import { ChevronRight } from "lucide-react";

import { stateLabel, stateTone, toneColor } from "@/lib/format";
import type { StateTransition } from "@/lib/types";

const PRETTY: Record<string, string> = {
  TCP_CONNECTED: "TCP connected",
  PLAINTEXT_EMAIL: "Plaintext email",
  TLS_REQUESTED: "TLS requested",
  TLS_NEGOTIATION: "TLS negotiation",
};

/** The encryption-state machine path a session actually took, with the frame behind each step. */
export function StatePath({ transitions, finalState }: { transitions: StateTransition[]; finalState: string }) {
  const steps = transitions.length
    ? [{ state: transitions[0].from, frame: null as number | null, trigger: "connection" }, ...transitions.map((t) => ({ state: t.to, frame: t.frame, trigger: t.trigger }))]
    : [{ state: finalState, frame: null, trigger: "" }];

  return (
    <div className="flex flex-wrap items-stretch gap-1.5">
      {steps.map((s, i) => {
        const last = i === steps.length - 1;
        const color = last ? toneColor(stateTone(finalState)) : "hsl(var(--muted-foreground))";
        return (
          <div key={i} className="flex items-center gap-1.5">
            <div
              className="rounded-md border px-2.5 py-1.5"
              style={last ? { borderColor: `color-mix(in srgb, ${color} 45%, transparent)`, background: `color-mix(in srgb, ${color} 10%, transparent)` } : undefined}
            >
              <div className="text-xs font-medium" style={last ? { color } : undefined}>
                {PRETTY[s.state] ?? stateLabel(s.state)}
              </div>
              <div className="text-[10.5px] text-muted-foreground">
                {s.frame != null ? <span className="font-mono">#{s.frame}</span> : null}
                {s.frame != null && s.trigger ? " · " : ""}
                {s.trigger}
              </div>
            </div>
            {!last && <ChevronRight className="size-3.5 text-muted-foreground" />}
          </div>
        );
      })}
    </div>
  );
}
