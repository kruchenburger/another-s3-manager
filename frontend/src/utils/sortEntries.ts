import type { FileEntry } from "@/types/api";

export type SortColumn = "name" | "size" | "modified";
export type SortDirection = "asc" | "desc";
export interface SortState {
  column: SortColumn;
  direction: SortDirection;
}

export const DEFAULT_SORT: SortState = { column: "name", direction: "asc" };

export function isDefaultSort(s: SortState): boolean {
  return s.column === "name" && s.direction === "asc";
}

// Same column → flip direction; different column → that column, ascending.
export function nextSortForColumn(current: SortState, column: SortColumn): SortState {
  if (current.column === column) {
    return { column, direction: current.direction === "asc" ? "desc" : "asc" };
  }
  return { column, direction: "asc" };
}

// Case-insensitive, locale-aware collation. Deliberately NOT identical to the
// backend's ordinal Python `name.lower()` sort: Intl.Collator orders by UCA
// primary weights, where punctuation and symbols sort before digits and
// letters, and accented letters collate beside their base letter. So even
// plain-ASCII names can diverge from a codepoint comparison — "file_2" sorts
// BEFORE "file1" here, but after it in Python (`_` is 0x5F > `1` is 0x31).
// (Note it is NOT that punctuation is ignored: `ignorePunctuation` is false.)
//
// That divergence is fine — preferable, even. This function only runs for an
// EXPLICITLY REQUESTED sort (FileBrowser's default view skips it and shows
// the backend's per-chunk concatenated order unchanged — see the
// `sortedItems` comment in FileBrowser.tsx). When it does run, it re-sorts
// the whole merged multi-chunk array client-side, so the result is a single
// globally consistent order across the list, whereas the backend sorts each
// chunk independently, which can leave chunk 1's last item ordered after
// chunk 2's first.
//
// Hoisted to module scope: constructing an Intl.Collator is relatively
// expensive (it builds locale collation tables), so a single shared instance
// is reused across every comparison instead of rebuilding one per call —
// this function runs O(n log n) times per sort over a level that can hold
// 100k+ entries.
const collator = new Intl.Collator(undefined, { sensitivity: "accent" });
function compareName(a: FileEntry, b: FileEntry): number {
  return collator.compare(a.name, b.name);
}

// Folders always first (S3 prefixes have no size/date). Folders sort by name,
// following `direction` ONLY when column === "name", else name-ascending.
// Files sort by the active column, with a stable name-ascending tiebreak.
export function sortEntries(
  directories: FileEntry[],
  files: FileEntry[],
  sort: SortState,
): FileEntry[] {
  const dirDir = sort.column === "name" ? sort.direction : "asc";
  const dirs = [...directories].sort(
    (a, b) => compareName(a, b) * (dirDir === "asc" ? 1 : -1),
  );

  const factor = sort.direction === "asc" ? 1 : -1;
  const sortedFiles = [...files].sort((a, b) => {
    let primary = 0;
    if (sort.column === "size") {
      primary = a.size - b.size;
    } else if (sort.column === "modified") {
      const ta = a.last_modified ? Date.parse(a.last_modified) : 0;
      const tb = b.last_modified ? Date.parse(b.last_modified) : 0;
      primary = ta - tb;
    } else {
      primary = compareName(a, b);
    }
    if (primary !== 0) return primary * factor;
    return compareName(a, b); // stable name-asc tiebreak
  });

  return [...dirs, ...sortedFiles];
}
