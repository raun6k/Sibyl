import { useState, type FormEvent, type ReactNode } from "react"
import { ArrowRight, Check, ChevronDown, Eye, FlaskConical, FolderGit2 } from "lucide-react"
import { api, type WorkspaceInfo } from "@/api"

export function Home({ onReady, inShell = false, onDemo, demoBusy = false, demoError = "" }: {
  onReady: (workspace: WorkspaceInfo, path: string) => void
  inShell?: boolean
  onDemo?: () => void
  demoBusy?: boolean
  demoError?: string
}) {
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState("")
  const [created, setCreated] = useState<WorkspaceInfo | null>(null)

  async function connect(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (created) { onReady(created, "/repositories"); return }
    const form = new FormData(event.currentTarget)
    const name = String(form.get("name") || "").trim()
    const location = String(form.get("location") || "").trim()
    if (!name) return setError("Give your workspace a name to continue.")
    setBusy(true)
    setError("")
    try {
      const workspace = await api.createWorkspace(name)
      if (location) {
        try {
          await api.connect(workspace.workspace_id, {
            location,
            branch: String(form.get("branch") || "").trim() || "main",
            token_env: String(form.get("token_env") || "").trim(),
            sync_interval_minutes: 60,
          })
        } catch (exc) {
          setCreated(workspace)
          setError(`Your workspace was created, but the repository could not connect. ${exc instanceof Error ? exc.message : "Try again from Repositories."}`)
          setBusy(false)
          return
        }
      }
      onReady(workspace, location ? "/repositories" : "/")
    } catch (exc) {
      setError(exc instanceof Error ? exc.message : "Your workspace couldn't be created. Try again.")
      setBusy(false)
    }
  }

  return (
    <div className={inShell ? "" : "sib flex min-h-svh flex-col bg-background text-foreground"}>
      {!inShell ? (
        <header className="px-6 py-6 sm:px-10">
          <span className="flex items-center gap-2"><Eye className="size-5 text-primary" aria-hidden="true" /><span className="display text-2xl">Sibyl</span></span>
        </header>
      ) : null}
      <main className={`mx-auto w-full max-w-3xl px-6 pt-8 sm:px-10 ${inShell ? "pb-8" : "flex-1 pb-36"}`}>
        <h1 className="display max-w-xl text-4xl leading-tight sm:text-[44px]">{inShell ? "Make room for your next project." : "Your code. A clearer picture of risk."}</h1>
        <p className="mt-4 max-w-lg text-base leading-7 text-muted-foreground">Create a workspace for your team or project. Connect your code when you’re ready, and Sibyl will help you find what needs attention.</p>

        <form onSubmit={connect} className="mt-9 flex flex-col gap-6 rounded-2xl border border-hairline bg-panel p-6 sm:p-8">
          <Field label="Workspace name" hint="Use your team, company, or project name.">
            <input name="name" required maxLength={120} placeholder="e.g. Acme Engineering" autoComplete="organization" className="input min-h-11" />
          </Field>
          <Field label="Repository (optional)" hint="A public git URL or a folder on this machine. You can add this later.">
            <div className="input flex min-h-11 items-center gap-3 focus-within:border-input"><FolderGit2 className="size-4 shrink-0 text-muted-foreground" aria-hidden="true" /><input name="location" placeholder="https://github.com/your-org/your-repo" className="min-w-0 flex-1 bg-transparent placeholder:text-muted-foreground" /></div>
          </Field>
          <details className="group border-t border-border pt-4">
            <summary className="flex min-h-10 cursor-pointer list-none items-center justify-between gap-3 text-sm text-muted-foreground hover:text-foreground">Branch & private repository access<ChevronDown className="size-4 transition-transform group-open:rotate-180" aria-hidden="true" /></summary>
            <div className="mt-4 grid gap-5 sm:grid-cols-2">
              <Field label="Branch" hint="The branch Sibyl follows."><input name="branch" defaultValue="main" className="input" /></Field>
              <Field label="Token variable" hint="An environment variable name. Never paste a token."><input name="token_env" placeholder="GITHUB_TOKEN" pattern="[A-Z_][A-Z0-9_]*" className="input mono" /></Field>
            </div>
          </details>
          {error ? <p role="alert" className="text-sm text-critical">{error}</p> : null}
          <div className="flex flex-wrap items-center justify-between gap-4 border-t border-border pt-5">
            <span className="flex items-center gap-2 text-xs text-muted-foreground"><Check className="size-4 text-primary" aria-hidden="true" />Your workspace starts empty.</span>
            <button type="submit" disabled={busy || demoBusy} className="inline-flex min-h-11 items-center gap-3 rounded-full bg-primary px-6 py-2.5 text-sm font-medium text-primary-foreground enabled:hover:bg-primary-strong disabled:opacity-60">{busy ? "Creating workspace…" : created ? "Continue to workspace" : "Create workspace"}<ArrowRight className="size-4" aria-hidden="true" /></button>
          </div>
        </form>
        <p className="mt-5 max-w-xl text-sm leading-6 text-muted-foreground">Once connected, Sibyl discovers your services, checks their packages against public vulnerability sources, and brings uncertain cases to you.</p>
      </main>
      {!inShell && onDemo ? (
        <div className="fixed inset-x-0 bottom-0 border-t border-hairline bg-background px-6 pt-3 pb-[max(16px,env(safe-area-inset-bottom))] sm:px-10">
          {demoError ? <p role="alert" className="mb-2 max-w-sm text-sm text-critical">{demoError}</p> : null}
          <button type="button" onClick={onDemo} disabled={busy || demoBusy} className="inline-flex min-h-11 items-center gap-2 rounded-full border border-hairline bg-panel px-4 py-2 text-sm text-muted-foreground hover:bg-raised hover:text-foreground disabled:opacity-60"><FlaskConical className="size-4 text-primary" aria-hidden="true" />{demoBusy ? "Opening demo…" : "Explore the demo"}<ArrowRight className="size-4" aria-hidden="true" /></button>
          <p className="mt-1.5 text-xs text-muted-foreground">A guided tour with sample data. No repository needed.</p>
        </div>
      ) : null}
    </div>
  )
}

function Field({ label, hint, children }: { label: string; hint: string; children: ReactNode }) {
  return <label className="flex flex-col gap-2"><span className="text-sm font-medium">{label}</span>{children}<span className="text-xs leading-5 text-muted-foreground">{hint}</span></label>
}
