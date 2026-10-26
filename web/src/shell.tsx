import { useCallback, useEffect, useState, type ReactNode } from "react"
import { Link, NavLink, Outlet, useLocation, useNavigate } from "react-router"
import { Boxes, Brain, Eye, FolderGit2, HelpCircle, History, Inbox, LayoutDashboard, ListChecks, Menu, MessageSquare, Moon, Plus, Search, X } from "lucide-react"
import { AskDrawer } from "@/ask"
import { api, setApiWorkspace, type RunState, type WorkspaceInfo } from "@/api"
import { Home } from "@/home"
import { RunDialog } from "@/run-dialog"
import { ago, isActive, STAGE_LABEL, STAGE_PHRASE, STAGES } from "@/lib/format"
import { pickWorkspace, rememberWorkspace, rememberedWorkspace, type SourceHealth, type Workspace } from "@/workspace"

const themes = [
  { id: "dark", label: "Ink" },
  { id: "light", label: "Ivory" },
  { id: "contrast", label: "High contrast" },
] as const

type ThemeId = (typeof themes)[number]["id"]

function readTheme(): ThemeId {
  const current = document.documentElement.dataset.theme
  if (current === "light" || current === "contrast" || current === "dark") return current
  return "dark"
}

export function applyTheme(theme: ThemeId) {
  document.documentElement.dataset.theme = theme
  document.documentElement.classList.toggle("dark", theme !== "light")
  try {
    localStorage.setItem("sibyl-theme", theme)
  } catch {
    // The theme still applies for this visit.
  }
}

export function Shell() {
  const [workspaces, setWorkspaces] = useState<WorkspaceInfo[] | null>(null)
  const [current, setCurrent] = useState<WorkspaceInfo | null>(null)
  const [loadError, setLoadError] = useState("")
  const navigate = useNavigate()

  const refreshWorkspaces = useCallback(async () => {
    const body = await api.workspaces()
    setWorkspaces(body.workspaces)
    setCurrent((was) => {
      const next = pickWorkspace(body.workspaces, was?.workspace_id ?? rememberedWorkspace())
      if (next) setApiWorkspace(next.workspace_id)
      return next
    })
    return body.workspaces
  }, [])

  useEffect(() => {
    refreshWorkspaces().catch((exc: Error) => setLoadError(exc.message || "The API is not answering."))
  }, [refreshWorkspaces])

  function enter(workspace: WorkspaceInfo, path: string) {
    rememberWorkspace(workspace.workspace_id)
    setApiWorkspace(workspace.workspace_id)
    setCurrent(workspace)
    refreshWorkspaces().catch(() => undefined)
    navigate(path)
  }

  if (loadError) {
    return (
      <div className="sib flex min-h-svh items-center justify-center bg-background p-6 text-foreground">
        <p role="alert" className="max-w-[480px] text-center text-muted-foreground">
          Sibyl's API is not answering ({loadError}). Start it with <span className="mono">scripts/dev.sh</span> and reload.
        </p>
      </div>
    )
  }
  if (workspaces == null) return <div className="sib min-h-svh bg-background" aria-busy="true" />
  if (!current) return <Home onReady={enter} />
  return (
    <WorkspaceShell
      key={current.workspace_id}
      workspace={current}
      workspaces={workspaces}
      refreshWorkspaces={refreshWorkspaces}
      onSwitch={(id) => {
        const next = workspaces.find((item) => item.workspace_id === id)
        if (next) enter(next, "/")
      }}
      onNew={() => navigate("/start")}
    />
  )
}

function WorkspaceShell({
  workspace: current,
  workspaces,
  refreshWorkspaces,
  onSwitch,
  onNew,
}: {
  workspace: WorkspaceInfo
  workspaces: WorkspaceInfo[]
  refreshWorkspaces: () => Promise<WorkspaceInfo[]>
  onSwitch: (id: string) => void
  onNew: () => void
}) {
  const [theme, setTheme] = useState<ThemeId>(readTheme)
  const [inbox, setInbox] = useState(current.open_questions ?? 0)
  const [ask, setAsk] = useState(false)
  const [runDialog, setRunDialog] = useState(false)
  const [menu, setMenu] = useState(false)
  const [queue, setQueue] = useState<number | null>(null)
  const [runs, setRuns] = useState<RunState[] | null>(null)
  const [sources, setSources] = useState<SourceHealth[] | null>(null)
  const location = useLocation()

  const refreshRuns = useCallback(() => {
    api
      .runs()
      .then((body) => {
        setRuns(body.runs)
        // The queue only exists once a run has finished.
        if (!body.runs.some((run) => run.status === "DONE")) return setQueue(null)
        api.queue().then((queued) => setQueue(queued.needs_human.length)).catch(() => setQueue(null))
      })
      .catch(() => setRuns((current) => current ?? []))
    api.sources().then((body) => setSources(body.sources)).catch(() => setSources((current) => current ?? []))
  }, [])

  const refreshInbox = useCallback(() => {
    api.questions(current.workspace_id).then((body) => setInbox(body.questions.length)).catch(() => undefined)
  }, [current.workspace_id])

  useEffect(() => {
    refreshInbox()
    window.addEventListener("sibyl-inbox", refreshInbox)
    return () => window.removeEventListener("sibyl-inbox", refreshInbox)
  }, [refreshInbox])

  useEffect(() => {
    refreshRuns()
    window.addEventListener("sibyl-queue", refreshRuns)
    window.addEventListener("sibyl-runs", refreshRuns)
    return () => {
      window.removeEventListener("sibyl-queue", refreshRuns)
      window.removeEventListener("sibyl-runs", refreshRuns)
    }
  }, [refreshRuns])

  const active = runs?.find(isActive) ?? null

  // Poll only while a run is going, so the strip and the counts stay current.
  useEffect(() => {
    if (!active) return
    const timer = window.setInterval(refreshRuns, 3000)
    return () => window.clearInterval(timer)
  }, [active, refreshRuns])

  useEffect(() => {
    function onKey(event: KeyboardEvent) {
      if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === "j") {
        event.preventDefault()
        setAsk((open) => !open)
      }
    }
    window.addEventListener("keydown", onKey)
    return () => window.removeEventListener("keydown", onKey)
  }, [])

  function cycleTheme() {
    const index = themes.findIndex((item) => item.id === theme)
    const next = themes[(index + 1) % themes.length]
    applyTheme(next.id)
    setTheme(next.id)
  }

  const workspace: Workspace = {
    workspace: current,
    workspaces,
    switchWorkspace: onSwitch,
    refreshWorkspaces,
    inbox,
    refreshInbox,
    runs,
    sources,
    refreshRuns,
    openRunDialog: () => setRunDialog(true),
    openAsk: () => setAsk(true),
  }
  const latest = runs && runs.length ? runs[runs.length - 1] : null
  const themeNow = themes.find((item) => item.id === theme) ?? themes[0]

  const sidebar = (
    <Sidebar
      workspace={current}
      workspaces={workspaces}
      onSwitch={onSwitch}
      onNew={onNew}
      inbox={inbox}
      queue={queue}
      latest={latest}
      sources={sources}
      themeLabel={themeNow.label}
      onTheme={cycleTheme}
      onAsk={() => setAsk(true)}
      onNavigate={() => setMenu(false)}
    />
  )

  return (
    <div className="sib min-h-svh bg-background text-foreground lg:grid lg:grid-cols-[248px_minmax(0,1fr)]">
      <div className="hidden lg:block">{sidebar}</div>

      <header className="flex items-center justify-between border-b border-hairline px-4 py-3 lg:hidden">
        <Wordmark />
        <button type="button" aria-label="Open menu" onClick={() => setMenu(true)} className="rounded-md p-2 text-muted-foreground hover:bg-raised">
          <Menu className="size-5" aria-hidden="true" />
        </button>
      </header>
      {menu ? (
        <div className="fixed inset-0 z-30 bg-[var(--scrim)] lg:hidden" role="presentation" onClick={() => setMenu(false)}>
          <div className="h-full w-[272px] bg-background shadow-xl" onClick={(event) => event.stopPropagation()}>
            <div className="flex justify-end p-2">
              <button type="button" aria-label="Close menu" onClick={() => setMenu(false)} className="rounded-md p-2 text-muted-foreground hover:bg-raised">
                <X className="size-5" aria-hidden="true" />
              </button>
            </div>
            {sidebar}
          </div>
        </div>
      ) : null}

      <div className="min-w-0 lg:py-2 lg:pr-2">
        <div className="min-h-[calc(100svh-57px)] overflow-clip bg-panel lg:min-h-[calc(100svh-16px)] lg:rounded-2xl lg:border lg:border-hairline">
          {active && !location.pathname.startsWith(`/runs/${active.run_id}`) ? <RunStrip run={active} /> : null}
          <Outlet context={workspace} />
        </div>
      </div>

      {ask ? <AskDrawer onClose={() => setAsk(false)} /> : null}
      {runDialog ? <RunDialog sources={sources} demo={current.is_demo} onClose={() => setRunDialog(false)} /> : null}
    </div>
  )
}

function Wordmark() {
  return (
    <Link to="/" className="flex items-center gap-2 text-foreground no-underline">
      <span className="flex size-7 items-center justify-center rounded-full border border-hairline text-primary">
        <Eye className="size-4" aria-hidden="true" />
      </span>
      <span className="display text-[22px] leading-none">Sibyl</span>
    </Link>
  )
}

function Sidebar({
  workspace,
  workspaces,
  onSwitch,
  onNew,
  inbox,
  queue,
  latest,
  sources,
  themeLabel,
  onTheme,
  onAsk,
  onNavigate,
}: {
  workspace: WorkspaceInfo
  workspaces: WorkspaceInfo[]
  onSwitch: (id: string) => void
  onNew: () => void
  inbox: number
  queue: number | null
  latest: RunState | null
  sources: SourceHealth[] | null
  themeLabel: string
  onTheme: () => void
  onAsk: () => void
  onNavigate: () => void
}) {
  const navigate = useNavigate()
  const live = sources?.filter((item) => item.status === "live").length ?? 0
  const snapshot = sources?.filter((item) => item.status === "snapshot").length ?? 0
  const down = sources?.filter((item) => item.status !== "live" && item.status !== "snapshot").length ?? 0

  return (
    <aside aria-label="Sibyl" className="flex h-[calc(100svh-52px)] flex-col gap-6 px-4 pb-4 pt-5 lg:sticky lg:top-0 lg:h-svh">
      <div className="flex flex-col gap-3 px-2">
        <Wordmark />
        <div className="flex items-center gap-2">
          <label className="sr-only" htmlFor="workspace">Workspace</label>
          <select
            id="workspace"
            value={workspace.workspace_id}
            onChange={(event) => onSwitch(event.target.value)}
            className="input min-w-0 flex-1 py-1.5 text-sm"
          >
            {workspaces.map((item) => (
              <option key={item.workspace_id} value={item.workspace_id}>
                {item.name}{item.is_demo ? " (demo)" : ""}
              </option>
            ))}
          </select>
          <button type="button" onClick={onNew} aria-label="New workspace" title="New workspace" className="rounded-md border border-hairline p-1.5 text-muted-foreground hover:bg-raised hover:text-foreground">
            <Plus className="size-4" aria-hidden="true" />
          </button>
        </div>
        {workspace.is_demo ? (
          <p className="text-xs text-muted-foreground">
            <span className="rounded-full border border-hairline px-2 text-[12px] leading-5 text-primary">Demo</span> sample services and snapshots
          </p>
        ) : null}
      </div>

      <form
        role="search"
        className="flex items-center gap-2 rounded-lg border border-border bg-panel px-3 py-2 text-muted-foreground focus-within:border-input"
        onSubmit={(event) => {
          event.preventDefault()
          const q = String(new FormData(event.currentTarget).get("q") || "").trim()
          onNavigate()
          navigate(q ? `/patches?q=${encodeURIComponent(q)}` : "/patches")
        }}
      >
        <Search className="size-4 shrink-0" aria-hidden="true" />
        <label className="sr-only" htmlFor="search">Search CVEs, packages and services</label>
        <input id="search" name="q" placeholder="CVE, package, service" className="w-full min-w-0 bg-transparent text-foreground outline-none placeholder:text-dim" />
      </form>

      <nav aria-label="Primary" className="flex flex-col gap-0.5" onClick={onNavigate}>
        <Nav to="/" end icon={<LayoutDashboard className="size-4" aria-hidden="true" />}>Overview</Nav>
        <Nav to="/inbox" icon={<Inbox className="size-4" aria-hidden="true" />}>
          <span className="flex-1">Inbox</span>
          {inbox ? <span className="num text-xs font-medium text-primary">{inbox}</span> : null}
        </Nav>
        <Nav to="/repositories" icon={<FolderGit2 className="size-4" aria-hidden="true" />}>Repositories</Nav>
        <Nav to="/services" icon={<Boxes className="size-4" aria-hidden="true" />}>Services</Nav>
        <Nav to="/patches" icon={<ListChecks className="size-4" aria-hidden="true" />}>Patch list</Nav>
        <Nav to="/queue" icon={<HelpCircle className="size-4" aria-hidden="true" />}>
          <span className="flex-1">Needs you</span>
          {queue ? <span className="num text-xs font-medium text-primary">{queue}</span> : null}
        </Nav>
        {latest ? (
          <Nav to={`/runs/${latest.run_id}`} icon={<History className="size-4" aria-hidden="true" />}>Latest run</Nav>
        ) : null}
        <Nav to="/memory" icon={<Brain className="size-4" aria-hidden="true" />}>Memory</Nav>
      </nav>

      <button
        type="button"
        onClick={() => {
          onNavigate()
          onAsk()
        }}
        className="flex items-center gap-3 rounded-lg border border-hairline px-3 py-2 text-left text-foreground hover:bg-raised"
      >
        <MessageSquare className="size-4 text-primary" aria-hidden="true" />
        <span className="flex-1">Ask Sibyl</span>
        <kbd className="mono text-xs text-dim">⌘J</kbd>
      </button>

      <div className="mt-auto flex flex-col gap-3 border-t border-hairline px-2 pt-4 text-xs text-muted-foreground">
        <p className="flex flex-wrap items-center gap-x-3 gap-y-1" aria-label="Source health">
          {sources == null ? <span>Checking sources…</span> : null}
          {live ? <span><span className="text-success">●</span> {live} live</span> : null}
          {snapshot ? <span><span className="text-primary">◐</span> {snapshot} snapshot</span> : null}
          {down ? <span><span className="text-critical">○</span> {down} off</span> : null}
          {sources && sources.length === 0 ? <span>No source data yet</span> : null}
        </p>
        <p>Last run {latest ? ago(latest.started) : "never"}</p>
        <button type="button" onClick={onTheme} className="flex items-center gap-2 self-start rounded-md py-1 text-muted-foreground hover:text-foreground">
          <Moon className="size-4" aria-hidden="true" />
          Theme: {themeLabel}
        </button>
      </div>
    </aside>
  )
}

function Nav({ to, end, icon, children }: { to: string; end?: boolean; icon: ReactNode; children: ReactNode }) {
  return (
    <NavLink
      to={to}
      end={end}
      className={({ isActive }) =>
        `flex items-center gap-3 rounded-lg px-3 py-2 no-underline transition-colors duration-75 ${
          isActive ? "bg-raised font-medium text-foreground" : "text-muted-foreground hover:bg-raised/60 hover:text-foreground"
        }`
      }
    >
      {icon}
      {children}
    </NavLink>
  )
}

function RunStrip({ run }: { run: RunState }) {
  const index = Math.max(0, STAGES.indexOf(run.stage as (typeof STAGES)[number]))
  const percent = Math.round(((index + 0.5) / STAGES.length) * 100)
  return (
    <Link to={`/runs/${run.run_id}`} className="block border-b border-hairline px-6 py-3 text-foreground no-underline hover:bg-raised/40 sm:px-10">
      <div className="flex flex-wrap items-baseline justify-between gap-2">
        <span className="flex items-baseline gap-3">
          <span className="eyebrow sib-pulse text-primary">Running</span>
          <span className="display text-lg">{STAGE_PHRASE[run.stage] ?? "Working"}</span>
        </span>
        <span className="text-xs text-muted-foreground">
          <span className="num">{Math.round(run.elapsed_seconds ?? 0)}s</span> elapsed · <span className="text-primary">Watch live →</span>
        </span>
      </div>
      <div className="mt-2 h-[3px] overflow-hidden rounded-full bg-raised" role="progressbar" aria-valuenow={percent} aria-valuemin={0} aria-valuemax={100} aria-label="Run progress">
        <div className="h-full bg-primary transition-[width] duration-200" style={{ width: `${percent}%` }} />
      </div>
      <div className="mt-1.5 hidden justify-between text-xs sm:flex">
        {STAGES.map((stage, i) => (
          <span key={stage} className={i < index ? "text-foreground" : i === index ? "text-primary" : "text-dim"}>{STAGE_LABEL[stage]}</span>
        ))}
      </div>
    </Link>
  )
}

// Inside the shell: start another workspace from the same screen a new user sees.
// The page reloads into the new workspace so every screen starts from its data.
export function NewWorkspace() {
  return (
    <Home
      inShell
      onReady={(workspace, path) => {
        rememberWorkspace(workspace.workspace_id)
        window.location.assign(path)
      }}
    />
  )
}
