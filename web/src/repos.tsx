import { Select } from "@/components/ui/select"
import { useCallback, useEffect, useState, type FormEvent } from "react"
import { Link } from "react-router"
import { AlertTriangle, ChevronDown, FolderGit2, Loader2, RefreshCw, Trash2 } from "lucide-react"
import { api, type Repository, type Schedule, type SyncRecord } from "@/api"
import { PageHeader } from "@/components/page-header"
import { activityFailure } from "@/lib/activity-errors"
import { agoIso, until } from "@/lib/format"
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
  const [schedule, setSchedule] = useState<Schedule | null>(null)

  const load = useCallback(() => {
    api.repositories(workspace.workspace_id).then((body) => setRepos(body.repositories)).catch((exc: Error) => setError(exc.message))
    api.syncs(workspace.workspace_id).then((body) => setSyncs(body.syncs)).catch(() => undefined)
    if (!workspace.is_demo) api.schedule(workspace.workspace_id).then(setSchedule).catch(() => undefined)
  }, [workspace.workspace_id, workspace.is_demo])

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
        <PageHeader title="Repositories" meta="The demo uses sample services, not a repository." />
        <div className="mx-auto max-w-[900px] px-6 py-8 text-sm text-muted-foreground sm:px-10">
          Create your own workspace (the + next to the workspace name) to connect a repository.
        </div>
      </div>
    )
  }

  return (
    <div>
      <PageHeader
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
          <RepoCard
            key={repo.repo_id}
            repo={repo}
            syncs={syncs.filter((item) => item.repo_id === repo.repo_id)}
            poll={schedule?.repositories.find((item) => item.repo_id === repo.repo_id)}
            onChange={load}
          />
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
        <Select name="interval" defaultValue={60}>
          {INTERVALS.map((item) => (
            <option key={item.minutes} value={item.minutes}>{item.label}</option>
          ))}
        </Select>
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

function RepoCard({
  repo,
  syncs,
  poll,
  onChange,
}: {
  repo: Repository
  syncs: SyncRecord[]
  poll?: Schedule["repositories"][number]
  onChange: () => void
}) {
  const [error, setError] = useState("")
  const [acting, setActing] = useState(false)
  const syncing = repo.syncing || repo.status === "syncing"
  const latest = syncs[0]

  async function act(action: () => Promise<unknown>) {
    if (acting) return
    setActing(true)
    setError("")
    try {
      await action()
      onChange()
    } catch (exc) {
      setError(exc instanceof Error ? exc.message : "That didn't work.")
    } finally {
      setActing(false)
    }
  }

  return (
    <details data-repository className="group/repository min-w-0 rounded-2xl border border-border bg-surface">
      <summary className="flex min-w-0 cursor-pointer list-none items-center gap-3 rounded-2xl px-5 py-4 hover:bg-raised/40 [&::-webkit-details-marker]:hidden">
        <FolderGit2 className="size-4 shrink-0 text-primary" aria-hidden="true" />
        <div className="flex min-w-0 flex-1 flex-wrap items-center justify-between gap-x-5 gap-y-1">
          {/^https?:\/\//i.test(repo.location) ? (
            <a href={repo.location} target="_blank" rel="noreferrer" title={repo.location} className="min-w-0 max-w-full truncate text-sm font-medium text-foreground underline-offset-4 hover:text-primary hover:underline">{repo.location}</a>
          ) : <span title={repo.location} className="min-w-0 max-w-full truncate text-sm font-medium">{repo.location}</span>}
          <span className="shrink-0 text-xs text-muted-foreground">Last checked {poll ? (poll.last_poll ? agoIso(poll.last_poll) : "never") : "unavailable"}</span>
        </div>
        <ChevronDown className="size-4 shrink-0 text-muted-foreground transition-transform group-open/repository:rotate-180" aria-hidden="true" />
      </summary>

      <div className="@container min-w-0 border-t border-border px-5 py-5 [overflow-wrap:anywhere]">
        <div className="grid gap-6 @min-[620px]:grid-cols-[minmax(0,1fr)_240px]">
          <section aria-label="Repository details" className="min-w-0">
            <h3 className="mb-4 text-xs font-medium text-muted-foreground">Repository details</h3>
            <dl className="grid grid-cols-2 gap-x-5 gap-y-4 text-xs">
              <div><dt className="text-muted-foreground">Branch</dt><dd className="mono mt-1.5 text-foreground">{repo.branch}</dd></div>
              <div><dt className="text-muted-foreground">Source</dt><dd className="mt-1.5">{repo.kind === "git" ? "Git URL" : "Local folder"}</dd></div>
              <div><dt className="text-muted-foreground">Services</dt><dd className="num mt-1.5">{repo.services ?? 0}</dd></div>
              <div><dt className="text-muted-foreground">Scanned commit</dt><dd className="mono mt-1.5" title={repo.last_scanned_sha || undefined}>{repo.last_scanned_sha?.slice(0, 8) || "Not scanned yet"}</dd></div>
              <div><dt className="text-muted-foreground">Last synced</dt><dd className="mt-1.5">{repo.last_synced_at ? <time dateTime={repo.last_synced_at}>{agoIso(repo.last_synced_at)}</time> : "Never"}</dd></div>
              <div><dt className="text-muted-foreground">Status</dt><dd className={`mt-1.5 ${repo.status === "error" ? "text-critical" : syncing ? "text-primary" : "text-foreground"}`}>{syncing ? "Syncing" : repo.status === "error" ? "Sync failed" : latest ? syncLine(latest) : "Not scanned yet"}</dd></div>
            </dl>
          </section>

          <section aria-label="Automatic checks" className="min-w-0 @min-[620px]:border-l @min-[620px]:border-border @min-[620px]:pl-5">
            <h3 className="mb-4 text-xs font-medium text-muted-foreground">Automatic checks</h3>
            <label className="flex flex-col gap-2 text-xs">
              Check for new commits
              <Select value={repo.sync_interval_minutes} disabled={acting} onValueChange={(value) => act(() => api.updateRepository(repo.repo_id, { sync_interval_minutes: Number(value) }))} className="text-xs" aria-label="How often Sibyl checks for new commits">
                {INTERVALS.some((item) => item.minutes === repo.sync_interval_minutes) ? null : <option value={repo.sync_interval_minutes}>Every {repo.sync_interval_minutes} minutes</option>}
                {INTERVALS.map((item) => <option key={item.minutes} value={item.minutes}>{item.label}</option>)}
              </Select>
            </label>
            <p className="mt-3 text-xs leading-5 text-muted-foreground">Next check {poll ? until(poll.next_poll) : "unavailable"}</p>
          </section>
        </div>

        {repo.status === "error" && repo.error ? <RepositoryError error={repo.error} /> : null}
        {error ? <RepositoryError error={error} /> : null}

        <div className="mt-6 flex flex-wrap items-center justify-between gap-3 border-t border-border pt-4">
          <div className="flex flex-wrap items-center gap-2">
            <button type="button" disabled={syncing || acting} onClick={() => act(() => api.sync(repo.repo_id))} className="flex min-h-9 items-center gap-2 rounded-lg bg-primary/15 px-3 text-xs font-medium text-primary hover:bg-primary/25 disabled:opacity-50">
              {syncing ? <Loader2 className="size-3.5 animate-spin" aria-hidden="true" /> : <RefreshCw className="size-3.5" aria-hidden="true" />}{syncing ? "Syncing…" : "Sync now"}
            </button>
            <button type="button" disabled={syncing || acting} onClick={() => act(() => api.sync(repo.repo_id, true))} className="min-h-9 rounded-lg border border-border px-3 text-xs text-muted-foreground hover:bg-raised hover:text-foreground disabled:opacity-50">Full rescan</button>
          </div>
          <button type="button" disabled={syncing || acting} aria-label={`Disconnect ${repo.location}`} onClick={() => {
            if (window.confirm("Disconnect this repository? Its services and their questions are removed from the workspace.")) act(() => api.disconnect(repo.repo_id))
          }} className="flex min-h-9 items-center gap-2 rounded-lg px-3 text-xs text-critical hover:bg-critical/10 disabled:opacity-50"><Trash2 className="size-3.5" aria-hidden="true" />Disconnect</button>
        </div>

        {syncs.length ? (
          <details className="mt-4 border-t border-border pt-4">
            <summary className="w-fit cursor-pointer text-xs text-muted-foreground hover:text-foreground">Recent scans · {Math.min(syncs.length, 5)}</summary>
            <div className="mt-3 flex min-w-0 flex-col gap-3">{syncs.slice(0, 5).map((item) => <SyncDetail key={item.sync_id} sync={item} />)}</div>
          </details>
        ) : null}
        <details className="mt-4 border-t border-border pt-4">
          <summary className="w-fit cursor-pointer text-xs text-muted-foreground hover:text-foreground">Sync from a push or merge</summary>
          <div className="mt-3 min-w-0"><HookHint repoId={repo.repo_id} /></div>
        </details>
      </div>
    </details>
  )
}

function RepositoryError({ error }: { error: string }) {
  return (
    <div role="alert" className="mt-5 text-xs leading-5">
      <p className="flex items-start gap-2 text-critical"><AlertTriangle className="mt-0.5 size-3.5 shrink-0" aria-hidden="true" />{activityFailure(error, true)}</p>
      <details className="mt-2 text-muted-foreground"><summary className="w-fit cursor-pointer">Error details</summary><pre className="mono mt-2 max-h-40 overflow-y-auto whitespace-pre-wrap rounded-lg bg-panel p-3 [overflow-wrap:anywhere]">{error}</pre></details>
    </div>
  )
}

function syncLine(sync: SyncRecord) {
  if (sync.status === "running") return "Sync running"
  if (sync.status === "failed") return "Sync failed"
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
      {sync.status === "failed" && sync.error ? <RepositoryError error={sync.error} /> : null}
      <p className="mt-2 text-xs text-muted-foreground">{agoIso(sync.started_at)}</p>
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
