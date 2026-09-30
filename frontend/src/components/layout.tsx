import {
  Activity,
  FileDown,
  FileSearch,
  FolderArchive,
  GitCompareArrows,
  KeyRound,
  LayoutDashboard,
  ListOrdered,
  Moon,
  Network,
  Sigma,
  Sun,
  Wrench,
} from "lucide-react";
import { Fragment, useEffect, useMemo } from "react";
import { Link, NavLink, Outlet, useLocation, useMatch, useNavigate } from "react-router-dom";

import {
  Breadcrumb,
  BreadcrumbItem,
  BreadcrumbLink,
  BreadcrumbList,
  BreadcrumbPage,
  BreadcrumbSeparator,
} from "@/components/ui/breadcrumb";
import { Button } from "@/components/ui/button";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Separator } from "@/components/ui/separator";
import {
  Sidebar,
  SidebarContent,
  SidebarFooter,
  SidebarGroup,
  SidebarGroupContent,
  SidebarGroupLabel,
  SidebarHeader,
  SidebarInset,
  SidebarMenu,
  SidebarMenuBadge,
  SidebarMenuButton,
  SidebarMenuItem,
  SidebarProvider,
  SidebarTrigger,
} from "@/components/ui/sidebar";
import { useCaptures, useOverview } from "@/lib/api";
import { useTheme } from "@/lib/theme";

const LAST_CAPTURE = "sms-last-capture";

const WORKSPACE = [
  { to: "", label: "Overview", icon: LayoutDashboard, end: true },
  { to: "findings", label: "Findings & trace", icon: ListOrdered },
  { to: "sessions", label: "Sessions", icon: Network },
  { to: "crypto", label: "Cryptography", icon: KeyRound },
  { to: "starttls", label: "STARTTLS", icon: Activity },
  { to: "remediation", label: "Fix simulator", icon: Wrench },
  { to: "reports", label: "Reports", icon: FileDown },
];

const PLATFORM = [
  { to: "/", label: "Evidence", icon: FolderArchive, end: true },
  { to: "/drift", label: "Drift", icon: GitCompareArrows },
  { to: "/model", label: "Risk model", icon: Sigma },
];

function Logo() {
  return (
    <div className="flex items-center gap-2.5 px-1 py-1">
      <div className="grid size-8 place-items-center rounded-lg bg-primary text-primary-foreground">
        <svg viewBox="0 0 24 24" className="size-[18px]" fill="none" stroke="currentColor" strokeWidth={2} strokeLinejoin="round" strokeLinecap="round">
          <path d="M4 7h16v10H4z" />
          <path d="m4 7 8 6 8-6" />
          <path d="M15.5 19.5 17 21l3-3" />
        </svg>
      </div>
      <div className="min-w-0 leading-tight group-data-[collapsible=icon]:hidden">
        <div className="text-sm font-semibold">SecureMailScope</div>
        <div className="text-[11px] text-muted-foreground">Email crypto forensics</div>
      </div>
    </div>
  );
}

function CaptureSwitcher({ captureId }: { captureId?: string }) {
  const { data } = useCaptures();
  const navigate = useNavigate();
  const location = useLocation();
  const complete = (data?.items ?? []).filter((c) => c.status === "complete");

  return (
    <div className="px-2 group-data-[collapsible=icon]:hidden">
      <div className="mb-1.5 px-1 text-[11px] font-medium uppercase tracking-wider text-muted-foreground">Capture</div>
      <Select
        value={captureId ?? ""}
        onValueChange={(id) => {
          // Keep the section, drop any finding/session ref that belongs to the old capture.
          const sub = location.pathname.match(/^\/c\/[^/]+\/?([^/]*)/)?.[1] ?? "";
          navigate(`/c/${id}${sub ? `/${sub}` : ""}`);
        }}
      >
        <SelectTrigger className="h-9 bg-background text-left">
          <SelectValue placeholder="Select an analysed capture" />
        </SelectTrigger>
        <SelectContent>
          {complete.map((c) => (
            <SelectItem key={c.capture_id} value={c.capture_id}>
              <span className="font-mono text-xs text-muted-foreground">{c.ref}</span>{" "}
              <span className="text-sm">{c.original_filename}</span>
            </SelectItem>
          ))}
        </SelectContent>
      </Select>
    </div>
  );
}

function AppSidebar({ captureId }: { captureId?: string }) {
  const { data: overview } = useOverview(captureId);
  const critical = overview?.findings.by_severity?.CRITICAL ?? 0;
  const { pathname } = useLocation();
  const isActive = (to: string, end?: boolean) => (end ? pathname === to || pathname === `${to}/` : pathname.startsWith(to));

  return (
    <Sidebar collapsible="icon">
      <SidebarHeader className="gap-3 pt-3">
        <Logo />
        <CaptureSwitcher captureId={captureId} />
      </SidebarHeader>
      <SidebarContent>
        <SidebarGroup>
          <SidebarGroupLabel>Assessment</SidebarGroupLabel>
          <SidebarGroupContent>
            <SidebarMenu>
              {WORKSPACE.map((item) => (
                <SidebarMenuItem key={item.label}>
                  <SidebarMenuButton
                    asChild
                    isActive={!!captureId && isActive(`/c/${captureId}${item.to ? `/${item.to}` : ""}`, item.end)}
                    tooltip={item.label}
                    className={captureId ? undefined : "pointer-events-none opacity-40"}
                  >
                    <NavLink to={captureId ? `/c/${captureId}${item.to ? `/${item.to}` : ""}` : "/"} end={item.end}>
                      <item.icon />
                      <span>{item.label}</span>
                    </NavLink>
                  </SidebarMenuButton>
                  {item.to === "findings" && critical > 0 && (
                    <SidebarMenuBadge className="bg-sev-critical/15 text-sev-critical">{critical}</SidebarMenuBadge>
                  )}
                </SidebarMenuItem>
              ))}
            </SidebarMenu>
          </SidebarGroupContent>
        </SidebarGroup>
        <SidebarGroup>
          <SidebarGroupLabel>Platform</SidebarGroupLabel>
          <SidebarGroupContent>
            <SidebarMenu>
              {PLATFORM.map((item) => (
                <SidebarMenuItem key={item.label}>
                  <SidebarMenuButton asChild isActive={isActive(item.to, item.end)} tooltip={item.label}>
                    <NavLink to={item.to} end={item.end}>
                      <item.icon />
                      <span>{item.label}</span>
                    </NavLink>
                  </SidebarMenuButton>
                </SidebarMenuItem>
              ))}
            </SidebarMenu>
          </SidebarGroupContent>
        </SidebarGroup>
      </SidebarContent>
      <SidebarFooter>
        <div className="flex items-center gap-2 px-2 pb-1 text-[11px] text-muted-foreground group-data-[collapsible=icon]:hidden">
          <FileSearch className="size-3.5" />
          Passive analysis · no server is contacted
        </div>
      </SidebarFooter>
    </Sidebar>
  );
}

const SECTION_LABEL: Record<string, string> = {
  findings: "Findings & trace",
  sessions: "Sessions",
  crypto: "Cryptography",
  starttls: "STARTTLS",
  remediation: "Fix simulator",
  reports: "Reports",
  drift: "Drift",
  model: "Risk model",
};

function Crumbs({ captureId }: { captureId?: string }) {
  const location = useLocation();
  const { data } = useCaptures();
  const capture = data?.items.find((c) => c.capture_id === captureId);
  const parts = location.pathname.split("/").filter(Boolean);

  const crumbs = useMemo(() => {
    const out: { label: string; to?: string }[] = [];
    if (parts[0] === "c" && captureId) {
      out.push({ label: capture ? `${capture.ref} · ${capture.original_filename}` : "Capture", to: `/c/${captureId}` });
      if (parts[2]) out.push({ label: SECTION_LABEL[parts[2]] ?? parts[2], to: `/c/${captureId}/${parts[2]}` });
      if (parts[3]) out.push({ label: decodeURIComponent(parts[3]) });
    } else if (parts[0]) {
      out.push({ label: SECTION_LABEL[parts[0]] ?? parts[0] });
    } else {
      out.push({ label: "Evidence" });
    }
    return out;
  }, [parts, captureId, capture]);

  return (
    <Breadcrumb>
      <BreadcrumbList>
        {crumbs.map((c, i) => (
          <Fragment key={i}>
            {i > 0 && <BreadcrumbSeparator />}
            <BreadcrumbItem>
              {i < crumbs.length - 1 && c.to ? (
                <BreadcrumbLink asChild>
                  <Link to={c.to}>{c.label}</Link>
                </BreadcrumbLink>
              ) : (
                <BreadcrumbPage className="max-w-[40ch] truncate">{c.label}</BreadcrumbPage>
              )}
            </BreadcrumbItem>
          </Fragment>
        ))}
      </BreadcrumbList>
    </Breadcrumb>
  );
}

export function Layout() {
  const match = useMatch("/c/:captureId/*");
  const routeCapture = match?.params.captureId;
  const { theme, toggle } = useTheme();

  useEffect(() => {
    if (routeCapture) {
      try {
        localStorage.setItem(LAST_CAPTURE, routeCapture);
      } catch {
        /* storage unavailable */
      }
    }
  }, [routeCapture]);

  let captureId = routeCapture;
  if (!captureId) {
    try {
      captureId = localStorage.getItem(LAST_CAPTURE) ?? undefined;
    } catch {
      captureId = undefined;
    }
  }

  return (
    <SidebarProvider>
      <AppSidebar captureId={captureId} />
      <SidebarInset className="min-w-0">
        <header className="sticky top-0 z-20 flex h-12 shrink-0 items-center gap-2 border-b bg-background/85 px-3 backdrop-blur">
          <SidebarTrigger className="-ml-1" />
          <Separator orientation="vertical" className="mr-1 h-4" />
          <div className="min-w-0 flex-1">
            <Crumbs captureId={routeCapture} />
          </div>
          <Button variant="ghost" size="icon" className="size-8" onClick={toggle} aria-label="Toggle theme">
            {theme === "dark" ? <Sun className="size-4" /> : <Moon className="size-4" />}
          </Button>
        </header>
        <main className="mx-auto w-full max-w-[1600px] flex-1 space-y-6 p-4 md:p-6">
          <Outlet />
        </main>
      </SidebarInset>
    </SidebarProvider>
  );
}
