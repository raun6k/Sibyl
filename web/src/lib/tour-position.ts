export type TourRect = { left: number; top: number; width: number; height: number }
export type TourPlacement = TourRect & { side: "top" | "bottom" | "left" | "right" | "center" }

// Keep the guide inside the viewport and separate from the highlighted target.
export function placeTour(target: TourRect | null, viewport: { width: number; height: number }, card: { width: number; height: number }): TourPlacement {
  const margin = 12
  const gap = 16
  const width = Math.min(card.width, viewport.width - margin * 2)
  const height = Math.min(card.height, viewport.height - margin * 2)
  const clamp = (value: number, max: number) => Math.max(margin, Math.min(value, max - margin))
  const center = { left: (viewport.width - width) / 2, top: (viewport.height - height) / 2, width, height, side: "center" as const }
  if (!target) return center
  const below = target.top + target.height + gap
  const above = target.top - height - gap
  const left = clamp(target.left + target.width / 2 - width / 2, viewport.width - width)
  if (below + height <= viewport.height - margin) return { left, top: below, width, height, side: "bottom" }
  if (above >= margin) return { left, top: above, width, height, side: "top" }
  const top = clamp(target.top + target.height / 2 - height / 2, viewport.height - height)
  if (target.left + target.width + gap + width <= viewport.width - margin) return { left: target.left + target.width + gap, top, width, height, side: "right" }
  if (target.left - gap - width >= margin) return { left: target.left - gap - width, top, width, height, side: "left" }
  // Very short viewports use a scrollable bottom sheet; the target remains outlined.
  return { ...center, top: viewport.height - height - margin }
}
