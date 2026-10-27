// Browser notifications while the tab is open (D23: in-app only, nothing is sent anywhere).

export function notificationsAllowed(): boolean {
  return typeof Notification !== "undefined" && Notification.permission === "granted"
}

export async function requestNotifications(): Promise<boolean> {
  if (typeof Notification === "undefined") return false
  const answer = await Notification.requestPermission()
  return answer === "granted"
}

// Activity kinds worth interrupting someone for.
const LOUD = new Set(["questions", "needs_human", "approval", "triage", "sync_failed", "triage_failed", "job_failed"])

export function notify(kind: string, title: string) {
  if (!LOUD.has(kind) || !notificationsAllowed() || document.visibilityState === "visible") return
  try {
    new Notification("Sibyl", { body: title, tag: kind })
  } catch {
    // Some browsers only allow notifications from a service worker; the feed still shows it.
  }
}
