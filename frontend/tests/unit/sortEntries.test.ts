import { describe, it, expect } from "vitest";
import type { FileEntry } from "@/types/api";
import {
  DEFAULT_SORT,
  isDefaultSort,
  nextSortForColumn,
  sortEntries,
  type SortState,
} from "@/utils/sortEntries";

const dir = (name: string): FileEntry => ({
  name,
  is_directory: true,
  size: 0,
});

const file = (
  name: string,
  size: number,
  last_modified?: string,
): FileEntry => ({ name, is_directory: false, size, last_modified });

const names = (entries: FileEntry[]) => entries.map((e) => e.name);

const ALL_SORTS: SortState[] = [
  { column: "name", direction: "asc" },
  { column: "name", direction: "desc" },
  { column: "size", direction: "asc" },
  { column: "size", direction: "desc" },
  { column: "modified", direction: "asc" },
  { column: "modified", direction: "desc" },
];

describe("sortEntries", () => {
  it("keeps folders first for every column and direction", () => {
    const dirs = [dir("zeta"), dir("alpha")];
    const files = [
      file("aaa.txt", 5, "2026-01-05T00:00:00Z"),
      file("zzz.txt", 1, "2026-01-01T00:00:00Z"),
    ];
    for (const sort of ALL_SORTS) {
      const out = sortEntries(dirs, files, sort);
      expect(out).toHaveLength(4);
      expect(out[0].is_directory).toBe(true);
      expect(out[1].is_directory).toBe(true);
      expect(out[2].is_directory).toBe(false);
      expect(out[3].is_directory).toBe(false);
    }
  });

  it("sorts files by name ascending, case-insensitively (mirrors the backend)", () => {
    const out = sortEntries(
      [],
      [file("b.txt", 1), file("A.txt", 1), file("c.txt", 1)],
      { column: "name", direction: "asc" },
    );
    expect(names(out)).toEqual(["A.txt", "b.txt", "c.txt"]);
  });

  it("sorts files by name descending", () => {
    const out = sortEntries(
      [],
      [file("b.txt", 1), file("A.txt", 1), file("c.txt", 1)],
      { column: "name", direction: "desc" },
    );
    expect(names(out)).toEqual(["c.txt", "b.txt", "A.txt"]);
  });

  it("sorts by size numerically, not as strings (9 before 100)", () => {
    const out = sortEntries([], [file("h.bin", 100), file("i.bin", 9)], {
      column: "size",
      direction: "asc",
    });
    // String order would put "100" before "9"; numeric order must not.
    expect(names(out)).toEqual(["i.bin", "h.bin"]);
  });

  it("sorts by size descending", () => {
    const out = sortEntries([], [file("h.bin", 100), file("i.bin", 9)], {
      column: "size",
      direction: "desc",
    });
    expect(names(out)).toEqual(["h.bin", "i.bin"]);
  });

  it("sorts by modified timestamp (oldest first asc, newest first desc)", () => {
    const older = file("old.txt", 1, "2026-01-01T00:00:00Z");
    const newer = file("new.txt", 1, "2026-06-01T00:00:00Z");
    expect(
      names(sortEntries([], [newer, older], { column: "modified", direction: "asc" })),
    ).toEqual(["old.txt", "new.txt"]);
    expect(
      names(sortEntries([], [older, newer], { column: "modified", direction: "desc" })),
    ).toEqual(["new.txt", "old.txt"]);
  });

  it("treats a missing last_modified as oldest", () => {
    const undated = file("undated.txt", 1);
    const dated = file("dated.txt", 1, "2026-01-01T00:00:00Z");
    expect(
      names(sortEntries([], [dated, undated], { column: "modified", direction: "asc" })),
    ).toEqual(["undated.txt", "dated.txt"]);
    expect(
      names(sortEntries([], [undated, dated], { column: "modified", direction: "desc" })),
    ).toEqual(["dated.txt", "undated.txt"]);
  });

  it("breaks size ties by name ascending — even when direction is desc", () => {
    const out = sortEntries(
      [],
      [file("bbb", 5), file("ccc", 5), file("aaa", 5)],
      { column: "size", direction: "desc" },
    );
    expect(names(out)).toEqual(["aaa", "bbb", "ccc"]);
  });

  it("keeps folders name-ascending when files sort by size or modified", () => {
    for (const sort of [
      { column: "size", direction: "desc" },
      { column: "modified", direction: "desc" },
    ] as SortState[]) {
      const out = sortEntries([dir("zeta"), dir("alpha")], [], sort);
      expect(names(out)).toEqual(["alpha", "zeta"]);
    }
  });

  it("reverses folders only when sorting by name descending", () => {
    const out = sortEntries([dir("alpha"), dir("zeta")], [], {
      column: "name",
      direction: "desc",
    });
    expect(names(out)).toEqual(["zeta", "alpha"]);
  });

  it("does not mutate its inputs", () => {
    const dirs = [dir("b"), dir("a")];
    const files = [file("y", 2), file("x", 1)];
    sortEntries(dirs, files, { column: "size", direction: "asc" });
    expect(names(dirs)).toEqual(["b", "a"]);
    expect(names(files)).toEqual(["y", "x"]);
  });
});

describe("nextSortForColumn", () => {
  it("flips direction when clicking the active column", () => {
    expect(nextSortForColumn({ column: "size", direction: "asc" }, "size")).toEqual({
      column: "size",
      direction: "desc",
    });
    expect(nextSortForColumn({ column: "size", direction: "desc" }, "size")).toEqual({
      column: "size",
      direction: "asc",
    });
  });

  it("switches to ascending when clicking a different column", () => {
    expect(nextSortForColumn({ column: "name", direction: "desc" }, "modified")).toEqual({
      column: "modified",
      direction: "asc",
    });
  });
});

describe("isDefaultSort", () => {
  it("is true only for name-ascending", () => {
    expect(isDefaultSort(DEFAULT_SORT)).toBe(true);
    expect(isDefaultSort({ column: "name", direction: "asc" })).toBe(true);
    expect(isDefaultSort({ column: "name", direction: "desc" })).toBe(false);
    expect(isDefaultSort({ column: "size", direction: "asc" })).toBe(false);
    expect(isDefaultSort({ column: "modified", direction: "desc" })).toBe(false);
  });
});
