import React from "react";
import ReactDOM from "react-dom/client";
import { BrowserRouter, Route, Routes } from "react-router-dom";
import "./index.css";
import { Layout } from "./components/Layout";
import { CapturesPage } from "./pages/Captures";
import { DriftPage } from "./pages/Drift";
import { FindingsPage } from "./pages/Findings";
import { GraphPage } from "./pages/Graph";
import { OverviewPage } from "./pages/Overview";
import { PosturePage } from "./pages/Posture";
import { SessionsPage } from "./pages/Sessions";
import { StarttlsPage } from "./pages/Starttls";

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <BrowserRouter>
      <Routes>
        <Route element={<Layout />}>
          <Route index element={<CapturesPage />} />
          <Route path="drift" element={<DriftPage />} />
          <Route path="c/:captureId">
            <Route index element={<OverviewPage />} />
            <Route path="posture" element={<PosturePage />} />
            <Route path="findings" element={<FindingsPage />} />
            <Route path="starttls" element={<StarttlsPage />} />
            <Route path="graph" element={<GraphPage />} />
            <Route path="sessions" element={<SessionsPage />} />
          </Route>
        </Route>
      </Routes>
    </BrowserRouter>
  </React.StrictMode>,
);
