import { useEffect, useState, type ReactNode } from "react"
import { Link, NavLink, Outlet, useNavigate } from "react-router"
import { Leaf, MessageSquare, Search } from "lucide-react"
import { AskDrawer } from "@/ask"
import { api } from "@/api"

const themes = [
  { id: "dark", label: "Dark" },
  { id: "light", label: "Light" },
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
  const [theme, setTheme] = useState<ThemeId>(readTheme)
  const [ask, setAsk] = useState(false)
  const [queue, setQueue] = useState<number | null>(null)
  const navigate = useNavigate()
  const current = themes.find((item) => item.id === theme) ?? themes[0]

  useEffect(() => {
    function refresh() {
      api.queue().then((body) => setQueue(body.needs_human.length)).catch(() => setQueue(null))
    }
    refresh()
    window.addEventListener("sibyl-queue", refresh)
    return () => window.removeEventListener("sibyl-queue", refresh)
  }, [])

  function cycleTheme() {
    const index = themes.findIndex((item) => item.id === theme)
    const next = themes[(index + 1) % themes.length]
    applyTheme(next.id)
    setTheme(next.id)
  }

  return (
    <div className="sib min-h-svh bg-background text-foreground">
      <header className="flex flex-wrap items-center gap-x-6 gap-y-2 border-b border-border bg-surface px-6 py-3">
        <Link to="/" className="flex items-center gap-2 text-foreground no-underline">
          <Leaf className="size-5 text-primary" aria-hidden="true" />
          <span className="text-[18px] font-semibold">Sibyl</span>
        </Link>
        <nav aria-label="Primary" className="flex flex-wrap gap-1">
          <Nav to="/" end>Inventory</Nav>
          <Nav to="/patches">Patch list</Nav>
          <Nav to="/queue">
            Needs human
            {queue != null && queue > 0 ? (
              <span className="num rounded-sm bg-primary px-1 text-xs font-semibold text-primary-foreground">{queue}</span>
            ) : null}
          </Nav>
          <Nav to="/memory">Memory</Nav>
        </nav>
        <form
          className="ml-auto flex w-full max-w-[280px] items-center gap-2 rounded-md border border-input bg-background px-3 py-2 text-muted-foreground sm:w-[280px]"
          onSubmit={(event) => {
            event.preventDefault()
            const data = new FormData(event.currentTarget)
            const q = String(data.get("q") || "")
            navigate(q ? `/patches?q=${encodeURIComponent(q)}` : "/patches")
          }}
        >
          <Search className="size-4" aria-hidden="true" />
          <label className="sr-only" htmlFor="search">Search CVE, package, service</label>
          <input id="search" name="q" placeholder="Search CVE, package, service…" className="w-full bg-transparent text-foreground outline-none" />
        </form>
        <button type="button" onClick={cycleTheme} className="h-8 rounded-md border border-border bg-transparent px-2 text-xs">
          {current.label}
        </button>
        <button type="button" onClick={() => setAsk(true)} className="flex items-center gap-2 rounded-md border border-input px-3 py-2">
          <MessageSquare className="size-4" aria-hidden="true" />
          Ask Sibyl
        </button>
      </header>
      <Outlet />
      {ask ? <AskDrawer onClose={() => setAsk(false)} /> : null}
    </div>
  )
}

function Nav({ to, end, children }: { to: string; end?: boolean; children: ReactNode }) {
  return (
    <NavLink
      to={to}
      end={end}
      className={({ isActive }) =>
        `flex items-center gap-2 rounded-md px-3 py-2 no-underline ${isActive ? "bg-raised font-medium text-foreground" : "text-muted-foreground"}`
      }
    >
      {children}
    </NavLink>
  )
}
