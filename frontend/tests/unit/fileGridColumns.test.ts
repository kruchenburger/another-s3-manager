import { describe, expect, it } from "vitest";
import { columnsForWidth, MIN_CARD } from "@/components/FileBrowser/FileGrid";

// GAP is 16 (Mantine md) inside FileGrid; formula: max(2, floor((w+16)/(180+16))).
describe("columnsForWidth (auto-fill semantics)", () => {
  it("keeps the pre-measure fallback at 6", () => {
    expect(columnsForWidth(0)).toBe(6);
  });

  it("never drops below 2 columns", () => {
    expect(columnsForWidth(200)).toBe(2);
    expect(columnsForWidth(390)).toBe(2);
  });

  it("fits as many >=180px columns as the width allows", () => {
    expect(columnsForWidth(768)).toBe(4); // floor(784/196)
    expect(columnsForWidth(1200)).toBe(6); // floor(1216/196)
    expect(columnsForWidth(1440)).toBe(7); // floor(1456/196) — was 6 pre-change
  });

  it("MIN_CARD is the documented 180px floor", () => {
    expect(MIN_CARD).toBe(180);
  });
});
