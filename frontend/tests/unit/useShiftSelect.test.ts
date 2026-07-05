import { describe, it, expect } from "vitest";
import { renderHook, act } from "@testing-library/react";
import { useShiftSelect } from "@/components/FileBrowser/useShiftSelect";

const ORDER = ["a", "b", "c", "d", "e", "f"];

describe("useShiftSelect", () => {
  it("starts with an empty selection and no anchor", () => {
    const { result } = renderHook(() => useShiftSelect());
    expect(result.current.selected.size).toBe(0);
  });

  it("plain click toggles a single item and sets the anchor", () => {
    const { result } = renderHook(() => useShiftSelect());
    act(() => result.current.handleToggle("b", false, ORDER));
    expect(result.current.selected.has("b")).toBe(true);
    expect(result.current.selected.size).toBe(1);
  });

  it("plain click again on the same item deselects it", () => {
    const { result } = renderHook(() => useShiftSelect());
    act(() => result.current.handleToggle("b", false, ORDER));
    act(() => result.current.handleToggle("b", false, ORDER));
    expect(result.current.selected.has("b")).toBe(false);
  });

  it("shift+click after a plain click selects the range INCLUSIVE downward", () => {
    const { result } = renderHook(() => useShiftSelect());
    act(() => result.current.handleToggle("b", false, ORDER)); // anchor=b
    act(() => result.current.handleToggle("e", true, ORDER)); // range b..e
    expect([...result.current.selected].sort()).toEqual(["b", "c", "d", "e"]);
  });

  it("shift+click selects the range INCLUSIVE upward (target before anchor)", () => {
    const { result } = renderHook(() => useShiftSelect());
    act(() => result.current.handleToggle("e", false, ORDER)); // anchor=e
    act(() => result.current.handleToggle("b", true, ORDER)); // range b..e
    expect([...result.current.selected].sort()).toEqual(["b", "c", "d", "e"]);
  });

  it("shift+click when anchor is deselected, deselects the range", () => {
    const { result } = renderHook(() => useShiftSelect());
    // Pre-fill all
    act(() => result.current.toggleAll(ORDER));
    // First plain click toggles 'b' OFF (anchor=b, b deselected)
    act(() => result.current.handleToggle("b", false, ORDER));
    expect(result.current.selected.has("b")).toBe(false);
    // Shift-click on 'e': should DESELECT b..e (anchor's new state = off)
    act(() => result.current.handleToggle("e", true, ORDER));
    expect(result.current.selected.has("b")).toBe(false);
    expect(result.current.selected.has("c")).toBe(false);
    expect(result.current.selected.has("d")).toBe(false);
    expect(result.current.selected.has("e")).toBe(false);
    // a and f untouched
    expect(result.current.selected.has("a")).toBe(true);
    expect(result.current.selected.has("f")).toBe(true);
  });

  it("shift+click without a prior anchor falls back to a plain toggle", () => {
    const { result } = renderHook(() => useShiftSelect());
    act(() => result.current.handleToggle("c", true, ORDER));
    expect([...result.current.selected]).toEqual(["c"]);
  });

  it("shift+click when the anchor was filtered out falls back to plain toggle", () => {
    const { result } = renderHook(() => useShiftSelect());
    act(() => result.current.handleToggle("z", false, ["x", "y", "z"]));
    // Now the visible list changes (anchor 'z' no longer present)
    act(() => result.current.handleToggle("a", true, ORDER));
    expect(result.current.selected.has("a")).toBe(true);
    // No range applied — z is preserved (it was selected previously), a added.
    expect([...result.current.selected].sort()).toEqual(["a", "z"]);
  });

  it("does not advance the anchor on a range op", () => {
    const { result } = renderHook(() => useShiftSelect());
    act(() => result.current.handleToggle("b", false, ORDER)); // anchor=b
    act(() => result.current.handleToggle("d", true, ORDER)); // range b..d, anchor stays at b
    // Next shift-click extends from b, not from d.
    act(() => result.current.handleToggle("a", true, ORDER));
    // Range b..a goes upward: includes a and b. d and c remain from previous range.
    expect([...result.current.selected].sort()).toEqual(["a", "b", "c", "d"]);
  });

  it("toggleAll selects everything in visible order when none selected", () => {
    const { result } = renderHook(() => useShiftSelect());
    act(() => result.current.toggleAll(ORDER));
    expect(result.current.selected.size).toBe(ORDER.length);
  });

  it("toggleAll deselects everything when all are selected", () => {
    const { result } = renderHook(() => useShiftSelect());
    act(() => result.current.toggleAll(ORDER));
    act(() => result.current.toggleAll(ORDER));
    expect(result.current.selected.size).toBe(0);
  });

  it("toggleAll clears the anchor (so subsequent shift+click acts as plain)", () => {
    const { result } = renderHook(() => useShiftSelect());
    act(() => result.current.handleToggle("b", false, ORDER)); // anchor=b
    act(() => result.current.toggleAll(ORDER)); // clears anchor
    act(() => result.current.handleToggle("d", true, ORDER));
    // No range b..d should be applied; selection from toggleAll persists,
    // and 'd' gets toggled OFF (was selected, plain toggle deselects).
    expect(result.current.selected.has("d")).toBe(false);
    // Others from toggleAll remain selected
    expect(result.current.selected.has("a")).toBe(true);
    expect(result.current.selected.has("b")).toBe(true);
    expect(result.current.selected.has("c")).toBe(true);
  });

  it("clear() empties the selection and resets the anchor", () => {
    const { result } = renderHook(() => useShiftSelect());
    act(() => result.current.handleToggle("b", false, ORDER));
    act(() => result.current.clear());
    expect(result.current.selected.size).toBe(0);
    // Subsequent shift+click acts as plain (anchor is gone).
    act(() => result.current.handleToggle("d", true, ORDER));
    expect([...result.current.selected]).toEqual(["d"]);
  });
});
