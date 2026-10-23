import { useState } from "react"
import { Leaf } from "lucide-react"
import { Button } from "@/components/ui/button"

const themes = [
  { id: "dark", label: "Dark" },
  { id: "light", label: "Light" },
  { id: "contrast", label: "High contrast" },
] as const

type ThemeId = (typeof themes)[number]["id"]

const severities = [
  { name: "Critical", glyph: "◆", color: "var(--critical)" },
  { name: "High", glyph: "▲", color: "var(--high)" },
  { name: "Medium", glyph: "■", color: "var(--medium)" },
  { name: "Low", glyph: "▼", color: "var(--low)" },
  { name: "Info", glyph: "●", color: "var(--info)" },
] as const

function readTheme(): ThemeId {
  const current = document.documentElement.dataset.theme
  if (current === "light" || current === "contrast" || current === "dark") {
    return current
  }
  return "dark"
}

function applyTheme(theme: ThemeId) {
  document.documentElement.dataset.theme = theme
  document.documentElement.classList.toggle("dark", theme !== "light")
  try {
    localStorage.setItem("sibyl-theme", theme)
  } catch {
    // Private mode and blocked storage still keep the theme for this visit.
  }
}

export default function App() {
  const [theme, setTheme] = useState<ThemeId>(readTheme)
  const current = themes.find((item) => item.id === theme) ?? themes[0]

  function cycleTheme() {
    const index = themes.findIndex((item) => item.id === theme)
    const next = themes[(index + 1) % themes.length]
    applyTheme(next.id)
    setTheme(next.id)
  }

  return (
    <div className="sib min-h-svh bg-background text-foreground">
      <header className="flex items-center gap-4 border-b border-border bg-surface px-6 py-3">
        <div className="flex items-center gap-2">
          <Leaf className="size-4 text-primary" aria-hidden="true" />
          <span className="text-[18px] leading-6 font-semibold">Sibyl</span>
        </div>
        <p className="text-muted-foreground">Foundations</p>
        <div className="ml-auto">
          <Button type="button" variant="outline" onClick={cycleTheme}>
            {current.label}
          </Button>
        </div>
      </header>
      <main className="mx-auto flex max-w-3xl flex-col gap-6 px-6 py-8">
        <section className="rounded-lg border border-border bg-surface p-6">
          <h1 className="text-2xl leading-8 font-semibold">Design tokens</h1>
          <p className="mt-2 max-w-xl text-muted-foreground">
            Slate and azure, with paper and cobalt and a high-contrast theme.
            Product screens are built in a later phase.
          </p>
          <p className="mono mt-4 text-foreground">CVE-2024-10080</p>
        </section>
        <section className="flex flex-wrap gap-2" aria-label="Severity scale">
          {severities.map((item) => (
            <span
              key={item.name}
              className="inline-flex h-5 items-center gap-1 rounded-sm px-2 text-xs leading-4 font-medium"
              style={{
                color: item.color,
                backgroundColor: `color-mix(in srgb, ${item.color} var(--tint), transparent)`,
              }}
            >
              <span aria-hidden="true">{item.glyph}</span>
              {item.name}
            </span>
          ))}
        </section>
      </main>
    </div>
  )
}
