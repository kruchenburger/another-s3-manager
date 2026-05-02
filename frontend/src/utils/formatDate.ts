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
