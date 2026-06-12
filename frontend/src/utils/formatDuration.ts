/**
 * Humanize a duration given in seconds into a short, user-facing string.
 *
 * Picks the largest sensible unit (days ≥ 1 day, else hours ≥ 1 hour, else
 * minutes) and rounds to the nearest whole unit. Used for presigned-URL
 * "expires in N …" copy in toasts. Presets always land on exact values.
 */
export function formatDuration(seconds: number): string {
  const plural = (n: number, unit: string) => `${n} ${unit}${n === 1 ? "" : "s"}`;
  if (seconds >= 86400) return plural(Math.round(seconds / 86400), "day");
  if (seconds >= 3600) return plural(Math.round(seconds / 3600), "hour");
  return plural(Math.round(seconds / 60), "minute");
}
