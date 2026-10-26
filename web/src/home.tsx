import { useState, type FormEvent, type ReactNode } from "react"
import { ArrowRight, Eye, FlaskConical, FolderGit2, GitBranch, KeyRound } from "lucide-react"
import { api, type WorkspaceInfo } from "@/api"

// The first screen for someone with no workspace yet: connect a repository. The demo is a corner button.
export function Home({ onReady, inShell = false }: { onReady: (workspace: WorkspaceInfo, path: string) => void; inShell?: boolean }) {
  const [busy, setBusy] = useState<"" | "connect" | "demo">("")
  const [error, setError] = useState("")

  async function connect(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const form = new FormData(event.currentTarget)
    const location = String(form.get("location") || "").trim()
    if (!location) return setError("Paste a git URL or the path of a folder on this machine.")
    setBusy("connect")
    setError("")
    try {
      const workspace = await api.createWorkspace(String(form.get("name") || "").trim() || "My workspace")
      try {
        await api.connect(workspace.workspace_id, {
          location,
          branch: String(form.get("branch") || "").trim() || "main",
          token_env: String(form.get("token_env") || "").trim(),
          sync_interval_minutes: 60,
        })
      } catch (exc) {
        await api.deleteWorkspace(workspace.workspace_id).catch(() => undefined)
        throw exc
      }
      onReady(workspace, "/repositories")
    } catch (exc) {
      setError(exc instanceof Error ? exc.message : "Sibyl couldn't connect that repository.")
      setBusy("")
    }
  }

  async function demo() {
    setBusy("demo")
    setError("")
    try {
      onReady(await api.loadDemo(), "/")
    } catch (exc) {
      setError(exc instanceof Error ? exc.message : "The demo didn't load.")
      setBusy("")
    }
  }

  return (
    <div className={inShell ? "" : "sib min-h-svh bg-background text-foreground"}>
      {inShell ? null : (
        <header className="flex items-center justify-between px-6 py-5 sm:px-10">
          <span className="flex items-center gap-2">
            <span className="flex size-7 items-center justify-center rounded-full border border-hairline text-primary">
              <Eye className="size-4" aria-hidden="true" />
            </span>
            <span className="display text-[22px] leading-none">Sibyl</span>
          </span>
          <button
            type="button"
            onClick={demo}
            disabled={busy !== ""}
            className="flex items-center gap-2 rounded-full border border-hairline px-4 py-2 text-sm text-muted-foreground hover:bg-raised hover:text-foreground disabled:opacity-60"
          >
            <FlaskConical className="size-4 text-primary" aria-hidden="true" />
            {busy === "demo" ? "Loading the demo…" : "Try the demo"}
          </button>
        </header>
      )}

      <main className="mx-auto flex max-w-[880px] flex-col gap-10 px-6 py-10 sm:px-10">
        <section className="flex flex-col gap-4">
          <span className="eyebrow text-primary">{inShell ? "New workspace" : "Start here"}</span>
          <h1 className="display text-[40px] leading-[46px]">Connect your code. Sibyl finds what is vulnerable and keeps watching.</h1>
          <p className="max-w-[680px] text-[15px] leading-6 text-muted-foreground">
            Sibyl reads your repository's manifests and lockfiles, finds each service and its dependencies, and works out
            what it can about each one. You confirm or correct it. Then it checks every package against seven public
            vulnerability sources, settles where they disagree, and tells you what to patch first.
          </p>
        </section>

        <form onSubmit={connect} className="flex flex-col gap-5 rounded-2xl border border-hairline bg-surface px-7 py-7">
          <div className="grid gap-5 sm:grid-cols-2">
            <Field label="Workspace name" hint="A team, product or company. You can rename it later.">
              <input name="name" placeholder="My workspace" className="input" />
            </Field>
            <Field label="Branch to follow" hint="Pushes and merges to this branch trigger a sync." icon={<GitBranch className="size-4" aria-hidden="true" />}>
              <input name="branch" defaultValue="main" className="input mono" />
            </Field>
          </div>
          <Field label="Repository" hint="A git URL (https or ssh), or the path of a folder on this machine." icon={<FolderGit2 className="size-4" aria-hidden="true" />}>
            <input name="location" required placeholder="https://github.com/your-org/your-repo.git" className="input mono" />
          </Field>
          <Field
            label="Token variable (private repositories only)"
            hint="The name of an environment variable that holds a read-only token, such as GITHUB_TOKEN. Never paste the token itself."
            icon={<KeyRound className="size-4" aria-hidden="true" />}
          >
            <input name="token_env" placeholder="GITHUB_TOKEN" className="input mono" pattern="[A-Z_][A-Z0-9_]*" />
          </Field>
          {error ? <p role="alert" className="text-sm text-critical">{error}</p> : null}
          <div className="flex flex-wrap items-center justify-between gap-3">
            <p className="text-xs text-muted-foreground">Sibyl only reads. It never pushes, and it sends only manifest and config lines to the model.</p>
            <button type="submit" disabled={busy !== ""} className="btn-gold inline-flex items-center gap-2 rounded-full px-6 py-2.5 text-sm font-medium disabled:opacity-60">
              {busy === "connect" ? "Connecting…" : "Connect and scan"}
              <ArrowRight className="size-4" aria-hidden="true" />
            </button>
          </div>
        </form>

        <ol className="grid gap-6 sm:grid-cols-3">
          {[
            ["It scans", "The first sync reads the whole repository. Later syncs read only what changed since."],
            ["You confirm", "Exposure, owner, criticality and data handled: Sibyl proposes, with the lines it read, and you settle."],
            ["It watches", "New commits and new advisories are checked on a schedule you set, or when you push."],
          ].map(([title, body], index) => (
            <li key={title} className="flex flex-col gap-1.5">
              <span className="display text-[22px] text-primary">{["I", "II", "III"][index]}</span>
              <span className="font-medium">{title}</span>
              <span className="text-sm text-muted-foreground">{body}</span>
            </li>
          ))}
        </ol>
      </main>
    </div>
  )
}

function Field({ label, hint, icon, children }: { label: string; hint: string; icon?: ReactNode; children: ReactNode }) {
  return (
    <label className="flex flex-col gap-1.5">
      <span className="flex items-center gap-2 text-sm font-medium">
        {icon ? <span className="text-dim">{icon}</span> : null}
        {label}
      </span>
      {children}
      <span className="text-xs text-muted-foreground">{hint}</span>
    </label>
  )
}
