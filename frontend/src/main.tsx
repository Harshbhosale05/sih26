import "@fontsource-variable/inter";
import "@fontsource-variable/jetbrains-mono";
import "./index.css";

import { QueryClientProvider } from "@tanstack/react-query";
import React from "react";
import ReactDOM from "react-dom/client";
import { BrowserRouter, Route, Routes } from "react-router-dom";

import { CaptureLayout } from "@/components/capture-layout";
import { Layout } from "@/components/layout";
import { Toaster } from "@/components/ui/sonner";
import { TooltipProvider } from "@/components/ui/tooltip";
import { queryClient } from "@/lib/api";
import { ThemeProvider } from "@/lib/theme";
import { AnalystPage } from "@/pages/analyst";
import { CapturesPage } from "@/pages/captures";
import { CryptoPage } from "@/pages/crypto";
import { DriftPage } from "@/pages/drift";
import { FindingsPage } from "@/pages/findings";
import { ModelPage } from "@/pages/model";
import { OverviewPage } from "@/pages/overview";
import { PqcPage } from "@/pages/pqc";
import { RemediationPage } from "@/pages/remediation";
import { ReportsPage } from "@/pages/reports";
import { SessionDetailPage } from "@/pages/session-detail";
import { SessionsPage } from "@/pages/sessions";
import { StarttlsPage } from "@/pages/starttls";
import { TracePage } from "@/pages/trace";

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <ThemeProvider>
      <QueryClientProvider client={queryClient}>
        <TooltipProvider delayDuration={200}>
          <BrowserRouter future={{ v7_startTransition: true, v7_relativeSplatPath: true }}>
            <Routes>
              <Route element={<Layout />}>
                <Route index element={<CapturesPage />} />
                <Route path="drift" element={<DriftPage />} />
                <Route path="model" element={<ModelPage />} />
                <Route path="c/:captureId" element={<CaptureLayout />}>
                  <Route index element={<OverviewPage />} />
                  <Route path="analyst" element={<AnalystPage />} />
                  <Route path="findings" element={<FindingsPage />} />
                  <Route path="findings/:ref" element={<TracePage />} />
                  <Route path="sessions" element={<SessionsPage />} />
                  <Route path="sessions/:ref" element={<SessionDetailPage />} />
                  <Route path="crypto" element={<CryptoPage />} />
                  <Route path="pqc" element={<PqcPage />} />
                  <Route path="starttls" element={<StarttlsPage />} />
                  <Route path="remediation" element={<RemediationPage />} />
                  <Route path="reports" element={<ReportsPage />} />
                </Route>
              </Route>
            </Routes>
          </BrowserRouter>
          <Toaster richColors position="bottom-right" />
        </TooltipProvider>
      </QueryClientProvider>
    </ThemeProvider>
  </React.StrictMode>,
);
