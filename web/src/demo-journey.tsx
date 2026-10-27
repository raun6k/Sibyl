import { useEffect, useRef, useState } from "react"
import { ArrowLeft, ArrowRight, Check, FlaskConical, X } from "lucide-react"
import { useLocation, useNavigate } from "react-router"
import { api, type Report, type RunState } from "@/api"
import { placeTour, type TourRect } from "@/lib/tour-position"

type Anchor = { key: string; rect: TourRect }

export function DemoJourney({ runs, onExit, onDismiss }: { runs: RunState[] | null; onExit: () => void; onDismiss: () => void }) {
  const [snapshot, setSnapshot] = useState<{ id: string; report: Report } | null>(null)
  const [error, setError] = useState("")
  const [retry, setRetry] = useState(0)
  const [anchor, setAnchor] = useState<Anchor | null>(null)
  const [missing, setMissing] = useState("")
  const [viewport, setViewport] = useState(() => ({ width: window.innerWidth, height: window.innerHeight }))
  const [cardSize, setCardSize] = useState({ width: 360, height: 300 })
  const modal = useRef<HTMLDialogElement>(null)
  const card = useRef<HTMLElement>(null)
  const title = useRef<HTMLHeadingElement>(null)
  const lastNavigation = useRef(0)
  const location = useLocation()
  const navigate = useNavigate()
  const runId = runs?.slice().reverse().find((run) => run.status === "DONE")?.run_id

  useEffect(() => {
    if (!runId) return
    let active = true
    api.report(runId).then((report) => {
      if (active) { setSnapshot({ id: runId, report }); setError("") }
    }).catch((exc: Error) => { if (active) setError(exc.message) })
    return () => { active = false }
  }, [runId, retry])

  const report = snapshot && snapshot.id === runId ? snapshot.report : null
  const cases = report ? [...report.ranked, ...report.needs_human, ...report.closed] : []
  const evidence = cases.find((item) => item.conflicts.length > 0) ?? cases[0]
  // One pass through how Sibyl works, in the order a new user meets it.
  const steps: { label: string; target?: string; path: string | null; title: string; body: string }[] = [
    { label: "Welcome", path: "/", title: "Which new vulnerabilities actually affect you?", body: "Sibyl answers that for your own code. This sample company has four services. In nine short stops you’ll see how Sibyl goes from a repository to a patch list, and how it learns from you." },
    { label: "Services", target: "service", path: "/services", title: "It starts from your code.", body: "Connect a repository and Sibyl scans it, makes a service of every folder with its own manifest (npm, PyPI, Maven, Go), and lists the exact package versions it runs." },
    { label: "Questions", target: "nav-inbox", path: "/services", title: "It asks before it assumes.", body: "From the code it reads, Sibyl proposes each service’s exposure, owner, criticality and data, and asks you to confirm them in the Inbox. Your answers weight every priority after that." },
    { label: "Agents at work", target: "trace", path: runId ? `/runs/${runId}` : null, title: "Six agents reconcile seven sources.", body: "Scout plans the run. Mapper links advisories from OSV, GitHub, NVD, CVE.org, CISA, EPSS and EUVD to your packages. Matcher checks version ranges. The Critic challenges weak verdicts and sends them back. Prioritiser scores, Reporter writes. Every step is recorded here." },
    { label: "Briefing", target: "briefing", path: "/", title: "The answer, in one paragraph.", body: "When a run finishes, the briefing says what to patch first and which decisions are waiting on you." },
    { label: "Patch list", target: "patch", path: "/patches", title: "What to patch first.", body: "Cases are ranked by known exploitation, EPSS, CVSS and how exposed the service is. The badges on the right show which sources agree with each verdict." },
    { label: "Evidence", target: "evidence", path: evidence ? `/cases/${encodeURIComponent(evidence.case_id)}` : null, title: "Every fact has a source.", body: "Open any case to see each fact with the record it came from. When sources disagree, the case file shows which one won and why." },
    { label: "Needs you", target: "review", path: "/queue", title: "When evidence falls short, it asks.", body: "Conflicting or thin evidence is never guessed at. Sibyl brings the case to you with every source’s position side by side, and you make the call." },
    { label: "Memory", target: "memory", path: "/memory", title: "It remembers your answers.", body: "A remembered answer decides the same case in later runs. The trust ledger decides which source wins a disagreement, and it only changes when you approve it." },
    { label: "Keeps watching", target: "nav-activity", path: "/", title: "Then it keeps watching.", body: "Sibyl re-scans when code changes, refreshes the feeds and re-triages on a schedule, reusing every verdict whose inputs didn’t change. Activity shows what it did while you were away. Explore the sample, or connect your own repository." },
  ]
  const [index, setIndex] = useState(0)
  const step = steps[index]
  const targetName = step?.target ?? ""
  const targetKey = `${location.pathname}:${targetName}:${retry}`
  const rect = anchor?.key === targetKey ? anchor.rect : null
  const placement = placeTour(rect, viewport, cardSize)

  useEffect(() => {
    const dialog = modal.current
    const previousFocus = document.activeElement
    const overflow = document.body.style.overflow
    document.body.style.overflow = "hidden"
    dialog?.showModal()
    title.current?.focus({ preventScroll: true })
    return () => {
      dialog?.close()
      document.body.style.overflow = overflow
      if (previousFocus instanceof HTMLElement && previousFocus.isConnected) previousFocus.focus({ preventScroll: true })
    }
  }, [])

  useEffect(() => {
    title.current?.focus({ preventScroll: true })
    const element = card.current
    if (!element) return
    const observer = new ResizeObserver(() => {
      setCardSize({ width: element.offsetWidth, height: element.offsetHeight })
    })
    observer.observe(element)
    return () => observer.disconnect()
  }, [targetKey])

  useEffect(() => {
    if (!targetName) return
    let target: HTMLElement | null = null
    let frame = 0
    const resize = new ResizeObserver(() => schedule())
    function measure() {
      frame = 0
      const found = document.querySelector<HTMLElement>(`[data-demo="${targetName}"]`)
      if (!found || found.getBoundingClientRect().height === 0) {
        setAnchor((old) => old?.key === targetKey ? null : old)
        return
      }
      if (found !== target) {
        resize.disconnect()
        target = found
        resize.observe(target)
        target.scrollIntoView({ block: "center", inline: "nearest", behavior: "instant" })
        // Reserve room for the message when centering a tall region on a small screen.
        const box = target.getBoundingClientRect()
        const height = card.current?.offsetHeight ?? 300
        const header = document.querySelector("[data-page-header]")
        const clearance = header && getComputedStyle(header).position === "sticky" ? header.getBoundingClientRect().height + 16 : 28
        if (box.top < clearance || (box.bottom + height + 28 > window.innerHeight && box.top - height - 16 < clearance)) {
          window.scrollBy({ top: box.top - clearance, behavior: "instant" })
        }
      }
      const box = found.getBoundingClientRect()
      // Account for horizontal scrolling inside tables as well as viewport edges.
      let left = Math.max(8, box.left - 6)
      let right = Math.min(window.innerWidth - 8, box.right + 6)
      let top = Math.max(8, box.top - 6)
      let bottom = Math.min(window.innerHeight - 8, box.bottom + 6)
      for (let parent = found.parentElement; parent; parent = parent.parentElement) {
        const style = getComputedStyle(parent)
        const bounds = parent.getBoundingClientRect()
        if (/(auto|scroll|hidden|clip)/.test(style.overflowX)) { left = Math.max(left, bounds.left); right = Math.min(right, bounds.right) }
        if (/(auto|scroll|hidden|clip)/.test(style.overflowY)) { top = Math.max(top, bounds.top); bottom = Math.min(bottom, bounds.bottom) }
      }
      if (right <= left || bottom <= top) { setAnchor(null); return }
      const next = { key: targetKey, rect: { left, top, width: right - left, height: bottom - top } }
      setAnchor((old) => JSON.stringify(old) === JSON.stringify(next) ? old : next)
    }
    function schedule() { if (!frame) frame = requestAnimationFrame(measure) }
    function onResize() {
      setViewport({ width: window.innerWidth, height: window.innerHeight })
      // Reposition the target and its guide together after a viewport change.
      target = null
      schedule()
    }
    const mutations = new MutationObserver(schedule)
    const root = document.getElementById("root")
    if (root) mutations.observe(root, { childList: true, subtree: true })
    const timeout = window.setTimeout(() => {
      if (!document.querySelector(`[data-demo="${targetName}"]`)) setMissing(targetKey)
    }, 12000)
    window.addEventListener("resize", onResize)
    window.addEventListener("scroll", schedule, true)
    window.visualViewport?.addEventListener("resize", onResize)
    schedule()
    return () => {
      resize.disconnect()
      mutations.disconnect()
      cancelAnimationFrame(frame)
      clearTimeout(timeout)
      window.removeEventListener("resize", onResize)
      window.removeEventListener("scroll", schedule, true)
      window.visualViewport?.removeEventListener("resize", onResize)
    }
  }, [targetKey, targetName])

  function go(next: number) {
    const destination = steps[next]?.path
    // Ignore repeated activation while a pointer press or key repeat is settling.
    if (!destination || performance.now() - lastNavigation.current < 500) return
    lastNavigation.current = performance.now()
    setIndex(next)
    if (destination !== location.pathname) navigate(destination)
  }

  function finish() {
    onDismiss()
    navigate("/")
    window.scrollTo({ top: 0, behavior: "instant" })
  }

  const waiting = !!targetName && !rect && missing !== targetKey
  const unavailable = !!targetName && !rect && missing === targetKey
  const last = index === steps.length - 1
  const nextUnavailable = !last && index >= 0 && !steps[index + 1]?.path
  const pointer = rect && placement.side !== "center" ? {
    left: placement.side === "left" ? placement.left + placement.width - 6 : placement.side === "right" ? placement.left - 6 : Math.max(placement.left + 24, Math.min(rect.left + rect.width / 2 - 6, placement.left + placement.width - 30)),
    top: placement.side === "bottom" ? placement.top - 6 : placement.side === "top" ? placement.top + placement.height - 6 : Math.max(placement.top + 24, Math.min(rect.top + rect.height / 2 - 6, placement.top + placement.height - 30)),
  } : null

  return (
    <dialog ref={modal} aria-labelledby="demo-title" aria-describedby="demo-description" onCancel={(event) => { event.preventDefault(); onDismiss() }} onKeyDown={(event) => {
      if (event.key !== "Tab") return
      const controls = Array.from(event.currentTarget.querySelectorAll<HTMLButtonElement>("button:not(:disabled)"))
      const first = controls[0]
      const last = controls[controls.length - 1]
      if (event.shiftKey && (document.activeElement === first || document.activeElement === title.current)) {
        event.preventDefault()
        last?.focus()
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault()
        first?.focus()
      }
    }} className="fixed inset-0 m-0 h-dvh max-h-none w-full max-w-none overflow-hidden border-0 bg-transparent p-0 text-foreground backdrop:bg-transparent">
      {rect ? (
        <div aria-hidden="true" className="pointer-events-none fixed inset-0">
          <div className="absolute inset-x-0 top-0 bg-black/70" style={{ height: rect.top }} />
          <div className="absolute left-0 bg-black/70" style={{ top: rect.top, height: rect.height, width: rect.left }} />
          <div className="absolute right-0 bg-black/70" style={{ top: rect.top, height: rect.height, width: Math.max(0, viewport.width - rect.left - rect.width) }} />
          <div className="absolute inset-x-0 bottom-0 bg-black/70" style={{ top: rect.top + rect.height }} />
          <div data-tour-spotlight className="absolute rounded-lg border-2 border-primary" style={{ ...rect }} />
        </div>
      ) : <div aria-hidden="true" className="fixed inset-0 bg-black/70" />}
      {pointer ? <div aria-hidden="true" className="pointer-events-none fixed size-3 rotate-45 bg-surface" style={pointer} /> : null}
      <section ref={card} data-tour-card data-placement={placement.side} className="fixed flex max-h-[calc(100dvh-24px)] w-[360px] max-w-[calc(100vw-24px)] flex-col overflow-y-auto rounded-2xl bg-surface p-5 shadow-[0_12px_48px_rgb(0_0_0/0.35)] selection:bg-primary/25" style={{ left: placement.left, top: placement.top }}>
        <div className="mb-4 flex items-center justify-between gap-3">
          <span className="flex items-center gap-2 text-xs text-muted-foreground"><FlaskConical className="size-4 text-primary" aria-hidden="true" />Demo · {index >= 0 ? `${index + 1} of ${steps.length}` : "Sample workspace"}</span>
          <button type="button" onClick={onDismiss} aria-label="Close tour" className="-mr-1 flex size-9 items-center justify-center rounded-md text-muted-foreground hover:bg-raised hover:text-foreground"><X className="size-4" aria-hidden="true" /></button>
        </div>
        <h2 ref={title} id="demo-title" tabIndex={-1} className="display text-[25px] leading-8" style={{ outline: "none" }}>{step?.title ?? "Return to the guided tour."}</h2>
        <p id="demo-description" className="mt-3 text-sm leading-6 text-muted-foreground">{step?.body ?? "Continue from the sample services, or exit to your own workspace."}</p>
        <p className="mt-3 text-xs text-muted-foreground">Sample data · saved results</p>
        <div aria-live="polite">
          {waiting ? <p role="status" className="mt-3 text-xs text-muted-foreground">Finding the highlighted area…</p> : null}
          {unavailable ? <p className="mt-3 text-sm text-muted-foreground">This area isn’t available yet. <button type="button" onClick={() => setRetry((value) => value + 1)} className="text-primary underline">Try again</button>, or continue the tour.</p> : null}
          {error ? <p role="alert" className="mt-3 text-sm text-critical">Saved evidence couldn’t load. <button type="button" onClick={() => setRetry((value) => value + 1)} className="underline">Retry</button></p> : null}
          {nextUnavailable && runs && !runId ? <p className="mt-3 text-sm text-muted-foreground">No completed sample run is available for the next stop. Close the tour to start a sample triage from Overview.</p> : null}
        </div>
        <div className="mt-5 flex items-center justify-between gap-3 border-t border-border pt-4">
          <button type="button" onClick={onExit} className="min-h-10 text-xs text-muted-foreground hover:text-foreground hover:underline">{last ? "Connect a repository" : "Exit demo"}</button>
          <div className="flex items-center gap-2">
            <button type="button" disabled={index <= 0} onClick={() => go(index - 1)} aria-label="Previous step" className="flex size-10 items-center justify-center rounded-full border border-border hover:bg-raised disabled:opacity-35"><ArrowLeft className="size-4" aria-hidden="true" /></button>
            <button type="button" disabled={nextUnavailable || waiting} onClick={() => last ? finish() : go(index < 0 ? 0 : index + 1)} className="flex min-h-10 items-center gap-2 rounded-full bg-primary px-4 text-sm font-medium text-primary-foreground enabled:hover:bg-primary-strong disabled:opacity-50">{last ? "Finish tour" : "Next"}{last ? <Check className="size-4" aria-hidden="true" /> : <ArrowRight className="size-4" aria-hidden="true" />}</button>
          </div>
        </div>
      </section>
    </dialog>
  )
}
