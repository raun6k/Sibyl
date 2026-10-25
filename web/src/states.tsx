import { Link } from "react-router"

export function Loading({ label }: { label: string }) {
  return (
    <div className="rounded-xl border border-border bg-surface p-4" aria-busy="true" aria-label={`Loading ${label}`}>
      <p className="text-sm font-medium">{label}</p>
      <div className="mt-3 h-3 w-1/2 animate-pulse rounded bg-raised" />
      <div className="mt-2 h-3 w-2/3 animate-pulse rounded bg-raised" />
    </div>
  )
}

export function PanelError({ message, onRetry }: { message: string; onRetry: () => void }) {
  return (
    <div role="alert" className="rounded-xl border border-border bg-surface p-4">
      <p className="font-medium">Something went wrong</p>
      <p className="text-sm text-muted-foreground">{message}</p>
      <button type="button" onClick={onRetry} className="mt-2 rounded-md border border-border px-3 py-1">Retry</button>
    </div>
  )
}

export function Empty({ title, action, href, onClick }: { title: string; action: string; href?: string; onClick?: () => void }) {
  return (
    <div className="rounded-xl border border-dashed border-input p-4">
      <p>{title}</p>
      {href ? <Link to={href}>{action}</Link> : <button type="button" onClick={onClick}>{action}</button>}
    </div>
  )
}
