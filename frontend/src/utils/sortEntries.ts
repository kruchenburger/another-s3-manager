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

// Case-insensitive, accent-sensitive — mirrors the backend's Python
// name.lower() sort so the client-side name order matches the S3-native
// order the backend already returns.
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
