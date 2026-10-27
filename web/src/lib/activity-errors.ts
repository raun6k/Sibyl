// Git/process output belongs in details; keep the primary message actionable.
export function activityFailure(raw: string, repository = false): string {
  if (repository) {
    if (/github\.com\/[^\s/'"]+\/[^\s/'"]+\/(?:tree|blob)\//i.test(raw)) return "This link points to a GitHub folder or file. Use the repository’s root URL instead."
    if (/authentication failed|permission denied|could not read username|403|401|access denied/i.test(raw)) return "Repository access was denied. Check the credentials and permissions."
    if (/repository .+not found|repository not found|404/i.test(raw)) return "Repository not found or inaccessible. Check the URL and repository access."
    if (/could not resolve|failed to connect|timed? out|network is unreachable/i.test(raw)) return "Couldn’t reach the repository. Check the connection and try again."
    return "Couldn’t sync the repository. Check its URL and access, then try again."
  }
  if (/timed? out|timeout/i.test(raw)) return "The task timed out. Try again, or review the details if it keeps happening."
  return "The task couldn’t finish. Review the details before trying again."
}
