import { Select } from "@/components/ui/select"
import { useCallback, useEffect, useState } from "react"
import { Link } from "react-router"
import { AlertCircle, Bell, BellOff, Circle, Loader2, RefreshCw } from "lucide-react"
import { api, streamActivity, type Activity, type Job, type Schedule } from "@/api"
import { PageHeader } from "@/components/page-header"
import { activityFailure } from "@/lib/activity-errors"
import { agoIso, JOB_LABEL, until } from "@/lib/format"
import { notificationsAllowed, requestNotifications } from "@/notify"
import { useWorkspace } from "@/workspace"

const FEED_INTERVALS = [
  { minutes: 360, label: "Every 6 hours" },
  { minutes: 720, label: "Twice a day" },
  { minutes: 1440, label: "Daily" },
  { minutes: 10080, label: "Weekly" },
]

// What the agents did on their own, live: syncs, feed refreshes, triages, memory curation.
export function ActivityScreen() {
  const { workspace } = useWorkspace()
  const [items, setItems] = useState<Activity[]>([])
  const [jobs, setJobs] = useState<Job[] | null>(null)
  const [schedule, setSchedule] = useState<Schedule | null>(null)
  const [allowed, setAllowed] = useState(notificationsAllowed())
  const [error, setError] = useState("")

  const loadJobs = useCallback(() => {
    api.jobs(workspace.workspace_id).then((body) => { setJobs(body.jobs); setError("") }).catch((exc: Error) => setError(exc.message))
    api.schedule(workspace.workspace_id).then(setSchedule).catch(() => undefined)
  }, [workspace.workspace_id])

  useEffect(() => {
    loadJobs()
    const stop = streamActivity(workspace.workspace_id, (item) => {
      setItems((current) => (current.some((row) => row.activity_id === item.activity_id) ? current : [item, ...current].slice(0, 300)))
      loadJobs()
    })
    return stop
  }, [workspace.workspace_id, loadJobs])

  const running = (jobs ?? []).filter((job) => job.status === "running" || job.status === "queued")

  const recent = (jobs ?? []).filter((job) => job.status === "done" || job.status === "failed").slice(0, 6)
  const failures = recent.filter((job) => job.status === "failed")
  // A sync emits a specific failure and a generic job failure for the same event.
  const specificFailures = new Set(items.filter((item) => item.kind !== "job_failed" && item.kind.endsWith("failed") && item.job_id).map((item) => item.job_id))
  const feed = items.filter((item) => !(item.kind === "job_failed" && item.job_id && specificFailures.has(item.job_id)))

  async function refreshNow() {
    try {
      await api.refreshFeeds(workspace.workspace_id)
      loadJobs()
    } catch (exc) {
      setError(exc instanceof Error ? exc.message : "The refresh did not start.")
    }
  }

  async function setFeedInterval(minutes: number) {
    try {
      await api.setFeedInterval(workspace.workspace_id, minutes)
      loadJobs()
    } catch (exc) {
      setError(exc instanceof Error ? exc.message : "Saving failed.")
    }
  }

  return (
    <div>
      <PageHeader
        title="Activity"
        compact
        meta={running.length ? `${running.length} jobs queued or running` : "The agents are idle"}
        actions={
          allowed ? (
            <span className="flex items-center gap-2 text-sm text-muted-foreground"><Bell className="size-4 text-primary" aria-hidden="true" />Notifications on while this tab is open</span>
          ) : (
            <button type="button" onClick={() => requestNotifications().then(setAllowed)} className="flex items-center gap-2 rounded-full border border-hairline px-4 py-2 text-sm hover:bg-raised">
              <BellOff className="size-4" aria-hidden="true" />Notify me in this browser
            </button>
          )
        }
      />
      <div className="mx-auto grid max-w-[1200px] gap-6 px-6 py-8 sm:px-10 lg:grid-cols-[minmax(0,1fr)_280px]">
        <section aria-label="Activity feed" className="min-w-0 flex flex-col gap-2">
          {error ? <div role="alert" className="min-w-0 border-b border-border pb-3"><p className="text-xs text-critical">Couldn’t complete the activity request. Review the details and try again.</p><FailureDetails error={error} /></div> : null}
          {items.length === 0 ? <p className="text-sm text-muted-foreground">Nothing yet. Syncs, feed refreshes and triages show up here as they happen.</p> : null}
          <ol className="flex flex-col gap-2">
            {feed.map((item) => {
              const failed = item.kind.endsWith("failed")
              const repository = item.kind === "sync_failed" || /^Sync of /i.test(item.title)
              const technical = (item.job_id ? jobs?.find((job) => job.job_id === item.job_id)?.error : null) || item.title
              const title = failed ? item.title.replace(/failed:[\s\S]*/i, "failed") : item.title
              return (
                <li key={item.activity_id} className="min-w-0 border-b border-border px-1 py-3 [overflow-wrap:anywhere]">
                  <div className="flex items-start justify-between gap-4">
                    <span className="text-xs font-medium leading-5">{title}</span>
                    <time dateTime={item.ts} className="shrink-0 text-[11px] leading-5 text-muted-foreground">{agoIso(item.ts)}</time>
                  </div>
                  {failed ? <p className="mt-1 text-xs leading-5 text-muted-foreground">{activityFailure(technical, repository)}</p> : null}
                  <div className="mt-1 flex flex-wrap items-center gap-x-3 gap-y-1 text-[11px] text-muted-foreground">
                    <span className={failed ? "text-critical" : ""}>{item.kind.replaceAll("_", " ")}</span>
                    {item.run_id && item.kind.startsWith("triage") ? <Link className="text-primary hover:underline" to={`/runs/${item.run_id}`}>Open run</Link> : null}
                    {item.kind === "questions" || item.kind === "needs_human" || item.kind === "approval" ? <Link className="text-primary hover:underline" to="/inbox">Open inbox</Link> : null}
                    {failed && repository ? <Link className="text-primary hover:underline" to="/repositories">Review repository</Link> : null}
                  </div>
                  {failed ? <FailureDetails error={technical} /> : null}
                </li>
              )
            })}
          </ol>
        </section>

        <aside className="flex min-w-0 flex-col gap-5">
          <section aria-label="Queue" className="min-w-0 rounded-xl border border-border bg-surface p-4">
            <div className="flex items-center justify-between gap-2">
              <h2 className="text-xs font-medium">Queue</h2>
              {running.length ? <span className="num text-[11px] text-muted-foreground">{running.length} active</span> : null}
            </div>
            {jobs == null ? <p className="mt-3 text-xs text-muted-foreground">Loading…</p> : null}
            {jobs && running.length === 0 ? <p className="mt-3 text-xs text-muted-foreground">Nothing queued.</p> : null}
            {running.length ? <ul className="mt-3 flex flex-col gap-3">
              {running.map((job) => (
                <li key={job.job_id} className="flex min-w-0 items-start gap-2 text-xs">
                  {job.status === "running" ? <Loader2 className="mt-0.5 size-3.5 shrink-0 animate-spin text-primary" aria-hidden="true" /> : <Circle className="mt-0.5 size-3.5 shrink-0 text-muted-foreground" aria-hidden="true" />}
                  <div className="min-w-0 flex-1"><p className="font-medium">{JOB_LABEL[job.kind] ?? job.kind}</p><p className="mt-0.5 text-[11px] text-muted-foreground">{job.status === "running" ? "Running" : "Queued"} · {job.trigger}</p></div>
                </li>
              ))}
            </ul> : null}
            {failures.length ? (
              <div className="mt-4 border-t border-border pt-3">
                <h3 className="mb-3 text-[11px] text-muted-foreground">Recent failures</h3>
                <ul className="flex flex-col gap-4">
                  {failures.map((job) => (
                    <li key={job.job_id} className="min-w-0 [overflow-wrap:anywhere]">
                      <div className="flex items-start gap-2"><AlertCircle className="mt-0.5 size-3.5 shrink-0 text-critical" aria-hidden="true" /><div className="min-w-0"><p className="text-xs font-medium">{JOB_LABEL[job.kind] ?? job.kind} failed</p><p className="mt-0.5 text-[11px] text-muted-foreground">{agoIso(job.finished_at)}</p></div></div>
                      <p className="mt-2 text-xs leading-5 text-muted-foreground">{activityFailure(job.error, job.kind === "repo_sync")}</p>
                      {job.kind === "repo_sync" ? <Link to="/repositories" className="mt-2 inline-block text-xs text-primary hover:underline">Review repository</Link> : null}
                      {job.error ? <FailureDetails error={job.error} /> : null}
                    </li>
                  ))}
                </ul>
              </div>
            ) : null}
            {recent.some((job) => job.status === "done") ? <p className="mt-4 border-t border-border pt-3 text-[11px] text-muted-foreground">{recent.filter((job) => job.status === "done").length} completed recently</p> : null}
          </section>

          {!workspace.is_demo ? (
            <div className="rounded-xl border border-hairline bg-surface p-4">
              <h2 className="text-xs font-medium">Advisory feeds</h2>
              <p className="mt-1 text-xs text-muted-foreground">
                Last read {agoIso(schedule?.feed.last_refresh)} · next {until(schedule?.feed.next_refresh)}. A change that touches a service queues its triage when it runs on change.
              </p>
              <label className="mt-3 flex flex-col gap-1 text-xs">
                Re-read the feeds
                <Select
                  value={schedule?.feed.interval_minutes ?? 1440}
                  onValueChange={(value) => setFeedInterval(Number(value))}
                  className="text-sm"
                >
                  {FEED_INTERVALS.map((item) => (
                    <option key={item.minutes} value={item.minutes}>{item.label}</option>
                  ))}
                </Select>
              </label>
              <button type="button" onClick={refreshNow} className="mt-3 flex items-center gap-2 rounded-full border border-hairline px-4 py-1.5 text-sm hover:bg-raised">
                <RefreshCw className="size-4" aria-hidden="true" />Refresh now
              </button>
            </div>
          ) : (
            <p className="text-xs text-muted-foreground">The demo replays frozen snapshots, so it has no schedule. Start a triage from the overview.</p>
          )}
        </aside>
      </div>
    </div>
  )
}

function FailureDetails({ error }: { error: string }) {
  return (
    <details className="mt-2 min-w-0 text-[11px] text-muted-foreground">
      <summary className="w-fit cursor-pointer rounded-sm py-1 hover:text-foreground">Details</summary>
      <pre className="mono mt-2 max-h-40 max-w-full overflow-y-auto whitespace-pre-wrap rounded-lg bg-panel p-3 text-[11px] leading-5 [overflow-wrap:anywhere]">{error}</pre>
    </details>
  )
}
