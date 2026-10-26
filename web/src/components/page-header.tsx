import type { ReactNode } from "react"

// The same top on every page: where you are, a one-line summary, and the page's actions.
export function PageHeader({ eyebrow, title, meta, actions }: { eyebrow?: string; title: string; meta?: ReactNode; actions?: ReactNode }) {
  return (
    <header className="sticky top-0 z-10 flex flex-wrap items-end justify-between gap-4 border-b border-hairline bg-panel px-6 pb-5 pt-7 sm:px-10">
      <div className="flex min-w-0 flex-col gap-1">
        {eyebrow ? <span className="eyebrow">{eyebrow}</span> : null}
        <h1 className="display text-[34px] leading-[40px]">{title}</h1>
        {meta ? <p className="text-sm text-muted-foreground">{meta}</p> : null}
      </div>
      {actions ? <div className="flex flex-wrap items-center gap-2">{actions}</div> : null}
    </header>
  )
}
