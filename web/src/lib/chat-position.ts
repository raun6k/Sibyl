export type ChatPosition = { x: number; y: number }

export function clampChat(position: ChatPosition | null, width: number, height: number, viewportWidth: number, viewportHeight: number): ChatPosition {
  const margin = 12
  const maxX = Math.max(margin, viewportWidth - width - margin)
  const maxY = Math.max(margin, viewportHeight - height - margin)
  return {
    x: Math.min(maxX, Math.max(margin, position?.x ?? viewportWidth - width - 24)),
    y: Math.min(maxY, Math.max(margin, position?.y ?? viewportHeight - height - 92)),
  }
}
