import clsx from "clsx";
import {
  Activity,
  ArrowLeftRight,
  Atom,
  FileSearch,
  FolderOpen,
  GitBranch,
  LayoutDashboard,
  ListTree,
  Mail,
  Menu,
  Moon,
  ShieldCheck,
  Sun,
  X,
} from "lucide-react";
import { ReactNode, useEffect, useState } from "react";
import { NavLink, Outlet, useLocation, useNavigate, useParams } from "react-router-dom";
import { useApi } from "../lib/api";
import type { CaptureList } from "../lib/types";

function useTheme() {
  const [dark, setDark] = useState(() => document.documentElement.classList.contains("dark"));
  useEffect(() => {
    document.documentElement.classList.toggle("dark", dark);
    try {
      localStorage.setItem("sms-theme", dark ? "dark" : "light");
    } catch {
      /* storage unavailable */
    }
  }, [dark]);
  return { dark, toggle: () => setDark((d) => !d) };
}

const CAPTURE_NAV = [
  { to: "", label: "Overview", icon: LayoutDashboard, end: true },
  { to: "posture", label: "Posture & PQC", icon: Atom },
  { to: "findings", label: "Findings", icon: FileSearch },
  { to: "starttls", label: "STARTTLS analytics", icon: Activity },
  { to: "graph", label: "Dependencies", icon: GitBranch },
  { to: "sessions", label: "Sessions", icon: ListTree },
];

function NavItem({ to, label, icon: Icon, end, onClick }: { to: string; label: string; icon: typeof Mail; end?: boolean; onClick?: () => void }) {
  return (
    <NavLink
      to={to}
      end={end}
      onClick={onClick}
      className={({ isActive }) =>
        clsx(
          "flex items-center gap-2.5 rounded-lg px-3 py-2 text-[13.5px] font-medium transition",
          isActive ? "bg-accent/10 text-accent" : "text-ink2 hover:bg-raised hover:text-ink",
        )
      }
    >
      <Icon size={16} />
      {label}
    </NavLink>
  );
}

function CaptureSwitcher({ current }: { current?: string }) {
  const { data } = useApi<CaptureList>("/api/captures?limit=200");
  const navigate = useNavigate();
  const location = useLocation();
  const complete = data?.items.filter((c) => c.status === "complete") ?? [];

  if (!complete.length) return null;
  return (
    <div className="px-3">
      <label className="mb-1.5 block text-[11px] font-semibold uppercase tracking-wider text-muted">Capture</label>
      <select
        value={current ?? ""}
        onChange={(e) => {
          const sub = current ? location.pathname.split(`/c/${current}`)[1] ?? "" : "";
          navigate(`/c/${e.target.value}${sub}`);
        }}
        className="w-full rounded-lg border border-line bg-surface px-2.5 py-2 text-[13px] text-ink focus:outline-none focus:ring-2 focus:ring-accent/40"
      >
        {!current && <option value="">Select a capture…</option>}
        {complete.map((c) => (
          <option key={c.capture_id} value={c.capture_id}>
            {c.ref} · {c.original_filename}
          </option>
        ))}
      </select>
    </div>
  );
}

function Sidebar({ onNavigate }: { onNavigate?: () => void }) {
  const { captureId } = useParams();
  return (
    <div className="flex h-full flex-col gap-6 py-5">
      <div className="flex items-center gap-2.5 px-5">
        <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-accent text-white">
          <ShieldCheck size={18} />
        </div>
        <div className="leading-tight">
          <div className="text-[15px] font-semibold text-ink">SecureMailScope</div>
          <div className="text-[11px] text-muted">Email crypto posture</div>
        </div>
      </div>

      <nav className="flex flex-col gap-0.5 px-2">
        <NavItem to="/" label="Captures" icon={FolderOpen} end onClick={onNavigate} />
        <NavItem to="/drift" label="Drift" icon={ArrowLeftRight} onClick={onNavigate} />
      </nav>

      <CaptureSwitcher current={captureId} />

      {captureId && (
        <nav className="flex flex-col gap-0.5 px-2">
          {CAPTURE_NAV.map((item) => (
            <NavItem
              key={item.label}
              to={`/c/${captureId}${item.to ? `/${item.to}` : ""}`}
              label={item.label}
              icon={item.icon}
              end={item.end}
              onClick={onNavigate}
            />
          ))}
        </nav>
      )}

      <div className="mt-auto px-5 text-[11px] leading-relaxed text-muted">
        Passive analysis only. Every verdict is deterministic and evidence-linked; ML adds context, never verdicts.
      </div>
    </div>
  );
}

export function Layout() {
  const { dark, toggle } = useTheme();
  const [open, setOpen] = useState(false);
  const location = useLocation();
  useEffect(() => setOpen(false), [location.pathname]);

  return (
    <div className="min-h-screen lg:grid lg:grid-cols-[256px_1fr]">
      <aside className="sticky top-0 hidden h-screen border-r border-line bg-surface lg:block">
        <Sidebar />
      </aside>

      {open && (
        <div className="fixed inset-0 z-40 lg:hidden">
          <div className="absolute inset-0 bg-black/40" onClick={() => setOpen(false)} />
          <aside className="relative h-full w-72 max-w-[85vw] border-r border-line bg-surface">
            <button
              className="absolute right-3 top-4 rounded-md p-1 text-ink2 hover:bg-raised"
              onClick={() => setOpen(false)}
              aria-label="Close menu"
            >
              <X size={18} />
            </button>
            <Sidebar onNavigate={() => setOpen(false)} />
          </aside>
        </div>
      )}

      <div className="flex min-w-0 flex-col">
        <header className="sticky top-0 z-30 flex h-14 items-center justify-between gap-3 border-b border-line bg-page/85 px-4 backdrop-blur sm:px-6 lg:px-8">
          <button className="rounded-md p-1.5 text-ink2 hover:bg-raised lg:hidden" onClick={() => setOpen(true)} aria-label="Open menu">
            <Menu size={20} />
          </button>
          <div className="flex-1" />
          <a href="/docs" target="_blank" rel="noreferrer" className="hidden text-[13px] text-ink2 hover:text-ink sm:block">
            API docs
          </a>
          <button
            onClick={toggle}
            className="rounded-lg border border-line bg-surface p-2 text-ink2 hover:text-ink"
            aria-label="Toggle theme"
          >
            {dark ? <Sun size={16} /> : <Moon size={16} />}
          </button>
        </header>
        <main className="mx-auto w-full max-w-[1400px] flex-1 px-4 py-6 sm:px-6 lg:px-8 lg:py-8">
          <Outlet />
        </main>
      </div>
    </div>
  );
}

export function Section({ title, children }: { title: string; children: ReactNode }) {
  return (
    <div className="mb-8">
      <h2 className="mb-3 text-[13px] font-semibold uppercase tracking-wider text-muted">{title}</h2>
      {children}
    </div>
  );
}
