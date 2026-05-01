const SECOND = 1000;
const MINUTE = 60 * SECOND;
const HOUR = 60 * MINUTE;
const DAY = 24 * HOUR;
const WEEK = 7 * DAY;

export function formatDate(iso: string): string {
  const then = new Date(iso).getTime();
  const now = Date.now();
  const diff = now - then;

  if (diff < MINUTE) return "just now";
  if (diff < HOUR) {
    const m = Math.floor(diff / MINUTE);
    return m === 1 ? "1 minute ago" : `${m} minutes ago`;
  }
  if (diff < DAY) {
    const h = Math.floor(diff / HOUR);
    return h === 1 ? "1 hour ago" : `${h} hours ago`;
  }
  if (diff < WEEK) {
    const d = Math.floor(diff / DAY);
    return d === 1 ? "1 day ago" : `${d} days ago`;
  }
  return new Date(iso).toLocaleDateString("en-US", { month: "short", day: "numeric", year: "numeric" });
}
