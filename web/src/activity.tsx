import { useCallback, useEffect, useState } from "react"
import { Link } from "react-router"
import { Bell, BellOff, Loader2, RefreshCw } from "lucide-react"
import { api, streamActivity, type Activity, type Job, type Schedule } from "@/api"
import { PageHeader } from "@/components/page-header"
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
    api.jobs(workspace.workspace_id).then((body) => setJobs(body.jobs)).catch((exc: Error) => setError(exc.message))
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
        eyebrow={workspace.name}
        title="Activity"
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
      <div className="mx-auto grid max-w-[1200px] gap-6 px-6 py-8 sm:px-10 lg:grid-cols-[minmax(0,1fr)_320px]">
        <section aria-label="Activity feed" className="flex flex-col gap-2">
          {error ? <p role="alert" className="text-sm text-critical">{error}</p> : null}
          {items.length === 0 ? <p className="text-sm text-muted-foreground">Nothing yet. Syncs, feed refreshes and triages show up here as they happen.</p> : null}
          <ol className="flex flex-col gap-2">
            {items.map((item) => (
              <li key={item.activity_id} className="rounded-xl border border-hairline bg-surface px-4 py-3">
                <div className="flex flex-wrap items-baseline justify-between gap-2">
                  <span className="text-sm">{item.title}</span>
                  <span className="text-xs text-muted-foreground">{agoIso(item.ts)}</span>
                </div>
                <div className="mt-1 flex flex-wrap gap-3 text-xs text-muted-foreground">
                  <span className="eyebrow">{item.kind.replace("_", " ")}</span>
                  {item.run_id && item.kind.startsWith("triage") ? <Link to={`/runs/${item.run_id}`}>Open the run</Link> : null}
                  {item.kind === "questions" || item.kind === "needs_human" || item.kind === "approval" ? <Link to="/inbox">Open the inbox</Link> : null}
                </div>
              </li>
            ))}
          </ol>
        </section>

        <aside className="flex flex-col gap-4">
          <div className="rounded-xl border border-hairline bg-surface p-4">
            <h2 className="text-sm font-semibold">Queue</h2>
            {jobs == null ? <p className="mt-2 text-sm text-muted-foreground">Loading…</p> : null}
            {jobs && running.length === 0 ? <p className="mt-2 text-sm text-muted-foreground">Nothing queued.</p> : null}
            <ul className="mt-2 flex flex-col gap-2">
              {running.map((job) => (
                <li key={job.job_id} className="flex items-center gap-2 text-sm">
                  {job.status === "running" ? <Loader2 className="size-4 animate-spin text-primary" aria-hidden="true" /> : <span className="text-dim">◌</span>}
                  <span className="flex-1">{JOB_LABEL[job.kind] ?? job.kind}</span>
                  <span className="text-xs text-muted-foreground">{job.trigger}</span>
                </li>
              ))}
            </ul>
            {jobs?.filter((job) => job.status === "done" || job.status === "failed").slice(0, 6).map((job) => (
              <p key={job.job_id} className="mt-2 text-xs text-muted-foreground">
                {JOB_LABEL[job.kind] ?? job.kind} {job.status === "failed" ? <span className="text-critical">failed</span> : "done"} {agoIso(job.finished_at)}
                {job.status === "failed" && job.error ? <span className="block text-critical">{job.error.slice(0, 160)}</span> : null}
              </p>
            ))}
          </div>

          {!workspace.is_demo ? (
            <div className="rounded-xl border border-hairline bg-surface p-4">
              <h2 className="text-sm font-semibold">Advisory feeds</h2>
              <p className="mt-1 text-xs text-muted-foreground">
                Last read {agoIso(schedule?.feed.last_refresh)} · next {until(schedule?.feed.next_refresh)}. A change that touches a service queues its triage when it runs on change.
              </p>
              <label className="mt-3 flex flex-col gap-1 text-xs">
                Re-read the feeds
                <select
                  value={schedule?.feed.interval_minutes ?? 1440}
                  onChange={(event) => setFeedInterval(Number(event.target.value))}
                  className="input text-sm"
                >
                  {FEED_INTERVALS.map((item) => (
                    <option key={item.minutes} value={item.minutes}>{item.label}</option>
                  ))}
                </select>
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
