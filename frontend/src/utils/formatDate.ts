const SECOND = 1000;
const MINUTE = 60 * SECOND;
const HOUR = 60 * MINUTE;
const DAY = 24 * HOUR;
const WEEK = 7 * DAY;

export function formatDate(iso: string): string {
  const then = new Date(iso).getTime();
  const now = Date.now();
  const diffMs = now - then;
  const future = diffMs < 0;
  const diff = Math.abs(diffMs);

  if (diff < MINUTE) return future ? "in less than a minute" : "just now";
  if (diff < HOUR) {
    const m = Math.floor(diff / MINUTE);
    const word = m === 1 ? "minute" : "minutes";
    return future ? `in ${m} ${word}` : `${m} ${word} ago`;
  }
  if (diff < DAY) {
    const h = Math.floor(diff / HOUR);
    const word = h === 1 ? "hour" : "hours";
    return future ? `in ${h} ${word}` : `${h} ${word} ago`;
  }
  if (diff < WEEK) {
    const d = Math.floor(diff / DAY);
    const word = d === 1 ? "day" : "days";
    return future ? `in ${d} ${word}` : `${d} ${word} ago`;
  }
  return new Date(iso).toLocaleDateString("en-US", { month: "short", day: "numeric", year: "numeric" });
}

// Wrapper that accepts nullable ISO strings (used by tooltips that show
// absolute timestamps next to relative ones — e.g. TokensTable's "Created"
// column). Returns "never" for null/undefined.
export function formatRelative(iso: string | null | undefined): string {
  if (!iso) return "never";
  return formatDate(iso);
}

// Absolute timestamp for tooltips: locale-aware "YYYY-MM-DD HH:mm" style.
// Used as the secondary display alongside formatRelative() — the relative
// label is the primary, the absolute is the tooltip detail.
export function formatAbsolute(iso: string | null | undefined): string {
  if (!iso) return "—";
  const d = new Date(iso);
  const pad = (n: number) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

// Time-of-day only ("02:14 PM" / "14:14"), locale-aware. Used for short-window
// expiry hints — the date is implicit ("expires today within the hour"), so
// HH:MM is the most useful detail. For full timestamps use formatAbsolute().
export function formatTimeOfDay(iso: string): string {
  return new Date(iso).toLocaleTimeString(undefined, {
    hour: "2-digit",
    minute: "2-digit",
  });
}
