import { FolderArchive, GitCompareArrows, Moon, Plus, Search, Sigma, Sun } from "lucide-react";
import { Fragment } from "react";
import { Link, NavLink, Outlet, useLocation, useMatch, useNavigate } from "react-router-dom";

import { CommandMenu, useCommandMenu } from "@/components/command-menu";
import { Dot } from "@/components/common";
import {
  Breadcrumb,
  BreadcrumbItem,
  BreadcrumbLink,
  BreadcrumbList,
  BreadcrumbPage,
  BreadcrumbSeparator,
} from "@/components/ui/breadcrumb";
import { Button } from "@/components/ui/button";
import { Separator } from "@/components/ui/separator";
import {
  Sidebar,
  SidebarContent,
  SidebarFooter,
  SidebarGroup,
  SidebarGroupAction,
  SidebarGroupContent,
  SidebarGroupLabel,
  SidebarHeader,
  SidebarInset,
  SidebarMenu,
  SidebarMenuButton,
  SidebarMenuItem,
  SidebarProvider,
  SidebarTrigger,
} from "@/components/ui/sidebar";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { useCaptures, useHealth } from "@/lib/api";
import { useTheme } from "@/lib/theme";

const NAV = [
  { to: "/", label: "Captures", icon: FolderArchive, end: true },
  { to: "/drift", label: "Drift", icon: GitCompareArrows },
  { to: "/model", label: "Risk model", icon: Sigma },
];

function Logo() {
  return (
    <Link to="/" className="flex items-center gap-2.5 px-1.5 py-1">
      <div className="grid size-7 shrink-0 place-items-center rounded-md bg-foreground text-background">
        <svg viewBox="0 0 24 24" className="size-4" fill="none" stroke="currentColor" strokeWidth={2.2} strokeLinejoin="round" strokeLinecap="round">
          <path d="M4 7h16v10H4z" />
          <path d="m4 7 8 6 8-6" />
        </svg>
      </div>
      <span className="truncate text-sm font-semibold tracking-tight group-data-[collapsible=icon]:hidden">SecureMailScope</span>
    </Link>
  );
}

function AppSidebar({ captureId }: { captureId?: string }) {
  const { pathname } = useLocation();
  const { data } = useCaptures();
  const health = useHealth();
  const navigate = useNavigate();
  const recent = (data?.items ?? []).filter((c) => c.status === "complete").slice(0, 6);

  return (
    <Sidebar collapsible="icon">
      <SidebarHeader className="h-12 justify-center border-b px-2">
        <Logo />
      </SidebarHeader>
      <SidebarContent>
        <SidebarGroup>
          <SidebarGroupContent>
            <SidebarMenu>
              {NAV.map((item) => (
                <SidebarMenuItem key={item.label}>
                  <SidebarMenuButton
                    asChild
                    tooltip={item.label}
                    isActive={item.end ? pathname === "/" : pathname.startsWith(item.to)}
                  >
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
        <SidebarGroup className="group-data-[collapsible=icon]:hidden">
          <SidebarGroupLabel>Recent captures</SidebarGroupLabel>
          <SidebarGroupAction title="New analysis" onClick={() => navigate("/?upload=1")}>
            <Plus />
          </SidebarGroupAction>
          <SidebarGroupContent>
            <SidebarMenu>
              {recent.map((c) => (
                <SidebarMenuItem key={c.capture_id}>
                  <SidebarMenuButton asChild isActive={c.capture_id === captureId} className="h-auto py-1.5">
                    <NavLink to={`/c/${c.capture_id}`}>
                      <div className="min-w-0">
                        <div className="truncate text-[13px]">{c.original_filename}</div>
                        <div className="font-mono text-[10.5px] text-muted-foreground">{c.ref}</div>
                      </div>
                    </NavLink>
                  </SidebarMenuButton>
                </SidebarMenuItem>
              ))}
              {!recent.length && <div className="px-2 py-1 text-xs text-muted-foreground">No analysed captures yet.</div>}
            </SidebarMenu>
          </SidebarGroupContent>
        </SidebarGroup>
      </SidebarContent>
      <SidebarFooter className="border-t">
        <div className="flex items-center gap-2 px-1.5 py-1 text-xs text-muted-foreground group-data-[collapsible=icon]:justify-center">
          <Dot color={health.data?.status === "ok" ? "hsl(var(--sev-ok))" : health.isError ? "hsl(var(--sev-critical))" : "hsl(var(--sev-medium))"} />
          <span className="group-data-[collapsible=icon]:hidden">
            {health.data?.status === "ok" ? "Analysis engine online" : health.isError ? "Engine unreachable" : "Connecting…"}
          </span>
          {health.data && <span className="ml-auto font-mono group-data-[collapsible=icon]:hidden">v{health.data.version}</span>}
        </div>
      </SidebarFooter>
    </Sidebar>
  );
}

const SECTIONS: Record<string, string> = {
  analyst: "AI Analyst",
  findings: "Findings",
  sessions: "Sessions",
  crypto: "Cryptography",
  pqc: "Post-Quantum",
  starttls: "STARTTLS",
  remediation: "Remediation",
  reports: "Report",
  drift: "Drift",
  model: "Risk model",
};

function Crumbs({ captureId }: { captureId?: string }) {
  const { pathname } = useLocation();
  const { data } = useCaptures();
  const parts = pathname.split("/").filter(Boolean);
  const capture = data?.items.find((c) => c.capture_id === captureId);

  const crumbs: { label: string; to?: string }[] = [{ label: "Captures", to: "/" }];
  if (parts[0] === "c" && captureId) {
    crumbs.push({ label: capture?.ref ?? "Capture", to: `/c/${captureId}` });
    if (parts[2]) crumbs.push({ label: SECTIONS[parts[2]] ?? parts[2], to: `/c/${captureId}/${parts[2]}` });
    if (parts[3]) crumbs.push({ label: decodeURIComponent(parts[3]) });
  } else if (parts[0]) {
    crumbs.splice(0, 1, { label: SECTIONS[parts[0]] ?? parts[0] });
  }

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
                <BreadcrumbPage className="font-mono text-[13px]">{c.label}</BreadcrumbPage>
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
  const captureId = match?.params.captureId;
  const { theme, toggle } = useTheme();
  const menu = useCommandMenu();

  return (
    <SidebarProvider>
      <AppSidebar captureId={captureId} />
      <SidebarInset className="min-w-0">
        <header className="sticky top-0 z-20 flex h-12 shrink-0 items-center gap-2 border-b bg-background/90 px-3 backdrop-blur">
          <SidebarTrigger className="-ml-1" />
          <Separator orientation="vertical" className="mr-1 h-4" />
          <div className="min-w-0 flex-1">
            <Crumbs captureId={captureId} />
          </div>
          <Button
            variant="outline"
            size="sm"
            className="h-8 w-56 justify-start gap-2 px-2.5 text-muted-foreground"
            onClick={() => menu.setOpen(true)}
          >
            <Search className="size-3.5" />
            <span className="text-xs">Search…</span>
            <kbd className="ml-auto rounded border bg-muted px-1.5 font-mono text-[10px]">⌘K</kbd>
          </Button>
          <Tooltip>
            <TooltipTrigger asChild>
              <Button variant="ghost" size="icon" className="size-8" onClick={toggle} aria-label="Toggle theme">
                {theme === "dark" ? <Sun className="size-4" /> : <Moon className="size-4" />}
              </Button>
            </TooltipTrigger>
            <TooltipContent>{theme === "dark" ? "Light theme" : "Dark theme"}</TooltipContent>
          </Tooltip>
        </header>
        {captureId ? (
          <Outlet />
        ) : (
          <main className="mx-auto w-full max-w-[1400px] flex-1 space-y-5 p-4 md:p-6">
            <Outlet />
          </main>
        )}
      </SidebarInset>
      <CommandMenu open={menu.open} setOpen={menu.setOpen} />
    </SidebarProvider>
  );
}
