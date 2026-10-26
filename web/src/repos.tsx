import { useCallback, useEffect, useState, type FormEvent } from "react"
import { Link } from "react-router"
import { AlertTriangle, ChevronRight, FolderGit2, GitBranch, Loader2, RefreshCw, Trash2 } from "lucide-react"
import { api, type Repository, type SyncRecord } from "@/api"
import { PageHeader } from "@/components/page-header"
import { ago } from "@/lib/format"
import { useWorkspace } from "@/workspace"

const INTERVALS = [
  { minutes: 15, label: "Every 15 minutes" },
  { minutes: 60, label: "Hourly" },
  { minutes: 360, label: "Every 6 hours" },
  { minutes: 1440, label: "Daily" },
]

export function Repositories() {
  const { workspace, refreshInbox } = useWorkspace()
  const [repos, setRepos] = useState<Repository[] | null>(null)
  const [syncs, setSyncs] = useState<SyncRecord[]>([])
  const [error, setError] = useState("")
  const [adding, setAdding] = useState(false)

  const load = useCallback(() => {
    api.repositories(workspace.workspace_id).then((body) => setRepos(body.repositories)).catch((exc: Error) => setError(exc.message))
    api.syncs(workspace.workspace_id).then((body) => setSyncs(body.syncs)).catch(() => undefined)
  }, [workspace.workspace_id])

  useEffect(load, [load])

  const busy = (repos ?? []).some((repo) => repo.syncing || repo.status === "syncing")
  useEffect(() => {
    if (!busy) {
      refreshInbox()
      return
    }
    const timer = window.setInterval(load, 3000)
    return () => window.clearInterval(timer)
  }, [busy, load, refreshInbox])

  if (workspace.is_demo) {
    return (
      <div>
        <PageHeader eyebrow={workspace.name} title="Repositories" meta="The demo uses sample services, not a repository." />
        <div className="mx-auto max-w-[900px] px-6 py-8 text-sm text-muted-foreground sm:px-10">
          Create your own workspace (the + next to the workspace name) to connect a repository.
        </div>
      </div>
    )
  }

  return (
    <div>
      <PageHeader
        eyebrow={workspace.name}
        title="Repositories"
        meta={repos ? `${repos.length} connected` : "Loading…"}
        actions={
          <button type="button" onClick={() => setAdding((open) => !open)} className="btn-gold rounded-full px-5 py-2 text-sm font-medium">
            {adding ? "Close" : "Connect repository"}
          </button>
        }
      />
      <div className="mx-auto flex max-w-[1100px] flex-col gap-6 px-6 py-8 sm:px-10">
        {error ? <p role="alert" className="text-sm text-critical">{error}</p> : null}
        {adding || (repos && repos.length === 0) ? (
          <ConnectForm
            workspaceId={workspace.workspace_id}
            onDone={() => {
              setAdding(false)
              load()
            }}
          />
        ) : null}
        {repos == null ? <p className="text-sm text-muted-foreground">Loading repositories…</p> : null}
        {(repos ?? []).map((repo) => (
          <RepoCard key={repo.repo_id} repo={repo} syncs={syncs.filter((item) => item.repo_id === repo.repo_id)} onChange={load} />
        ))}
      </div>
    </div>
  )
}

function ConnectForm({ workspaceId, onDone }: { workspaceId: string; onDone: () => void }) {
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState("")

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const form = new FormData(event.currentTarget)
    setBusy(true)
    setError("")
    try {
      await api.connect(workspaceId, {
        location: String(form.get("location") || "").trim(),
        branch: String(form.get("branch") || "").trim() || "main",
        token_env: String(form.get("token_env") || "").trim(),
        sync_interval_minutes: Number(form.get("interval") || 60),
      })
      onDone()
    } catch (exc) {
      setError(exc instanceof Error ? exc.message : "Sibyl couldn't connect that repository.")
    } finally {
      setBusy(false)
    }
  }

  return (
    <form onSubmit={submit} className="grid gap-4 rounded-2xl border border-hairline bg-surface px-6 py-6 sm:grid-cols-2">
      <label className="flex flex-col gap-1.5 sm:col-span-2">
        <span className="text-sm font-medium">Repository</span>
        <input name="location" required placeholder="https://github.com/your-org/your-repo.git or /path/to/folder" className="input mono" />
      </label>
      <label className="flex flex-col gap-1.5">
        <span className="text-sm font-medium">Branch</span>
        <input name="branch" defaultValue="main" className="input mono" />
      </label>
      <label className="flex flex-col gap-1.5">
        <span className="text-sm font-medium">Check for new commits</span>
        <select name="interval" defaultValue={60} className="input">
          {INTERVALS.map((item) => (
            <option key={item.minutes} value={item.minutes}>{item.label}</option>
          ))}
        </select>
      </label>
      <label className="flex flex-col gap-1.5 sm:col-span-2">
        <span className="text-sm font-medium">Token variable (private repositories)</span>
        <input name="token_env" placeholder="GITHUB_TOKEN" pattern="[A-Z_][A-Z0-9_]*" className="input mono" />
        <span className="text-xs text-muted-foreground">The name of an environment variable holding a read-only token. Never the token itself.</span>
      </label>
      {error ? <p role="alert" className="text-sm text-critical sm:col-span-2">{error}</p> : null}
      <div className="flex justify-end sm:col-span-2">
        <button type="submit" disabled={busy} className="btn-gold rounded-full px-6 py-2.5 text-sm font-medium disabled:opacity-60">
          {busy ? "Connecting…" : "Connect and scan"}
        </button>
      </div>
    </form>
  )
}

function RepoCard({ repo, syncs, onChange }: { repo: Repository; syncs: SyncRecord[]; onChange: () => void }) {
  const [open, setOpen] = useState(false)
  const [error, setError] = useState("")
  const syncing = repo.syncing || repo.status === "syncing"
  const latest = syncs[0]

  async function act(action: () => Promise<unknown>) {
    setError("")
    try {
      await action()
      onChange()
    } catch (exc) {
      setError(exc instanceof Error ? exc.message : "That didn't work.")
    }
  }

  return (
    <section className="rounded-2xl border border-hairline bg-surface">
      <div className="flex flex-wrap items-start justify-between gap-4 px-6 py-5">
        <div className="flex min-w-0 flex-col gap-1.5">
          <span className="flex items-center gap-2 font-medium">
            <FolderGit2 className="size-4 text-primary" aria-hidden="true" />
            <span className="mono truncate">{repo.location}</span>
          </span>
          <span className="flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-muted-foreground">
            <span className="flex items-center gap-1"><GitBranch className="size-3.5" aria-hidden="true" />{repo.branch}</span>
            <span>{repo.kind === "git" ? "git URL" : "local folder"}</span>
            <span>{repo.services ?? 0} services</span>
            <span>{repo.last_scanned_sha ? <span className="mono">{repo.last_scanned_sha.slice(0, 8)}</span> : "not scanned yet"}</span>
            <span>{repo.last_synced_at ? `synced ${ago(Date.parse(repo.last_synced_at) / 1000)}` : ""}</span>
            <span>checks {INTERVALS.find((item) => item.minutes === repo.sync_interval_minutes)?.label.toLowerCase() ?? `every ${repo.sync_interval_minutes} min`}</span>
          </span>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          {syncing ? (
            <span className="flex items-center gap-2 text-sm text-primary"><Loader2 className="size-4 animate-spin" aria-hidden="true" />Syncing</span>
          ) : (
            <>
              <button type="button" onClick={() => act(() => api.sync(repo.repo_id))} className="flex items-center gap-2 rounded-full border border-hairline px-4 py-1.5 text-sm hover:bg-raised">
                <RefreshCw className="size-4" aria-hidden="true" />Sync now
              </button>
              <button type="button" onClick={() => act(() => api.sync(repo.repo_id, true))} className="rounded-full border border-hairline px-4 py-1.5 text-sm text-muted-foreground hover:bg-raised">
                Full rescan
              </button>
              <button
                type="button"
                aria-label={`Disconnect ${repo.location}`}
                onClick={() => {
                  if (window.confirm("Disconnect this repository? Its services and their questions are removed from the workspace.")) act(() => api.disconnect(repo.repo_id))
                }}
                className="rounded-full border border-hairline p-2 text-muted-foreground hover:bg-raised hover:text-critical"
              >
                <Trash2 className="size-4" aria-hidden="true" />
              </button>
            </>
          )}
        </div>
      </div>
      {repo.status === "error" && repo.error ? (
        <p role="alert" className="flex items-start gap-2 border-t border-hairline px-6 py-3 text-sm text-critical">
          <AlertTriangle className="mt-0.5 size-4 shrink-0" aria-hidden="true" />
          {repo.error}
        </p>
      ) : null}
      {error ? <p role="alert" className="border-t border-hairline px-6 py-3 text-sm text-critical">{error}</p> : null}
      {latest ? (
        <div className="border-t border-hairline">
          <button type="button" aria-expanded={open} onClick={() => setOpen((value) => !value)} className="flex w-full items-center gap-2 px-6 py-3 text-left text-sm">
            <ChevronRight className={`size-4 text-dim transition-transform duration-150 ${open ? "rotate-90" : ""}`} aria-hidden="true" />
            <span className="flex-1">{syncLine(latest)}</span>
            <span className="text-xs text-muted-foreground">{ago(Date.parse(latest.started_at) / 1000)}</span>
          </button>
          {open ? (
            <div className="flex flex-col gap-4 px-6 pb-5">
              {syncs.slice(0, 5).map((item) => (
                <SyncDetail key={item.sync_id} sync={item} />
              ))}
              <HookHint repoId={repo.repo_id} />
            </div>
          ) : null}
        </div>
      ) : null}
    </section>
  )
}

function syncLine(sync: SyncRecord) {
  if (sync.status === "running") return "Sync running"
  if (sync.status === "failed") return `Sync failed: ${sync.error}`
  const summary = sync.summary
  if (summary.mode === "up_to_date") return "Up to date: no new commits"
  const found = summary.new_services?.length ?? 0
  const fresh = new Set((summary.new_services ?? []).map((item) => item.service_id))
  const packages = (summary.new_services ?? []).reduce((sum, item) => sum + item.components, 0)
  const changed = Object.entries(summary.services ?? {})
    .filter(([id]) => !fresh.has(id))
    .reduce((sum, [, item]) => sum + item.added + item.removed + item.changed, 0)
  const parts = [
    summary.mode === "incremental" ? "Changes since the last scan" : "Full scan",
    found ? `${found} new ${found === 1 ? "service" : "services"} with ${packages} packages` : null,
    changed ? `${changed} package changes` : null,
    summary.questions ? `${summary.questions} questions` : null,
  ]
  return parts.filter(Boolean).join(" · ")
}

function SyncDetail({ sync }: { sync: SyncRecord }) {
  const summary = sync.summary
  const failing = (summary.quality ?? []).filter((item) => item.invalid || item.error)
  return (
    <div className="rounded-xl border border-hairline px-4 py-3 text-sm">
      <p className="flex flex-wrap items-center gap-x-3 text-xs text-muted-foreground">
        <span className="mono">{(sync.from_sha ?? "").slice(0, 8) || "—"} → {(sync.to_sha ?? "").slice(0, 8) || "—"}</span>
        <span>{sync.mode}</span>
        <span>{sync.status}</span>
        {summary.seconds != null ? <span>{summary.seconds}s</span> : null}
      </p>
      {summary.new_services?.length ? (
        <p className="mt-2">
          New:{" "}
          {summary.new_services.map((item) => (
            <span key={item.service_id} className="mr-3"><span className="mono">{item.path || "(root)"}</span> · {item.components} packages</span>
          ))}
        </p>
      ) : null}
      {Object.entries(summary.services ?? {})
        .filter(([, item]) => item.diff && (item.added || item.removed || item.changed))
        .map(([id, item]) => (
          <div key={id} className="mt-2">
            <span className="font-medium">{id}</span>: +{item.added} −{item.removed} ~{item.changed}
            <ul className="mono mt-1 text-xs text-muted-foreground">
              {[...(item.diff?.changed ?? []), ...(item.diff?.added ?? []).map((line) => `+ ${line}`), ...(item.diff?.removed ?? []).map((line) => `− ${line}`)].slice(0, 8).map((line) => (
                <li key={line}>{line}</li>
              ))}
            </ul>
          </div>
        ))}
      {failing.length ? (
        <p className="mt-2 text-muted-foreground">
          Zetaris data quality:{" "}
          {failing.map((item) => (item.error ? `${item.rule} could not run` : `${item.invalid} fail “${item.meaning}”`)).join(" · ")}{" "}
          <Link to="/inbox">Review</Link>
        </p>
      ) : summary.quality?.length ? (
        <p className="mt-2 text-muted-foreground">Zetaris data quality: all {summary.quality.length} rules pass.</p>
      ) : null}
      {summary.limits?.length ? <p className="mt-2 text-xs text-muted-foreground">Limits: {summary.limits.join("; ")}</p> : null}
      {summary.not_covered && Object.keys(summary.not_covered).length ? (
        <p className="mt-1 text-xs text-muted-foreground">
          Not covered yet: {Object.entries(summary.not_covered).map(([name, count]) => `${count} ${name}`).join(", ")}
        </p>
      ) : null}
      {summary.skipped?.length ? <p className="mt-1 text-xs text-muted-foreground">Skipped test and example folders: {summary.skipped.slice(0, 6).join(", ")}</p> : null}
    </div>
  )
}

function HookHint({ repoId }: { repoId: string }) {
  return (
    <div className="text-xs text-muted-foreground">
      <p>Sync right after a push or merge: call this from a git hook (post-merge) or a CI step.</p>
      <code className="mono mt-1 block overflow-x-auto rounded-md bg-raised px-3 py-2 text-foreground">
        curl -X POST "http://127.0.0.1:8000/hooks/push?repo={repoId}"
      </code>
    </div>
  )
}
