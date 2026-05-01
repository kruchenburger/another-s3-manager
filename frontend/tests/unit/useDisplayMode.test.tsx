import { afterEach, describe, expect, it } from "vitest";
import { renderHook, act } from "@testing-library/react";
import { useDisplayMode } from "@/hooks/useDisplayMode";

describe("useDisplayMode", () => {
  afterEach(() => {
    localStorage.clear();
  });

  it("defaults to 'table' when no key set", () => {
    const { result } = renderHook(() => useDisplayMode("aws-prod", "images"));
    expect(result.current.mode).toBe("table");
  });

  it("persists set mode to localStorage", () => {
    const { result } = renderHook(() => useDisplayMode("aws-prod", "images"));
    act(() => {
      result.current.setMode("grid");
    });
    expect(result.current.mode).toBe("grid");
    expect(localStorage.getItem("display:aws-prod:images")).toBe("grid");
  });

  it("reads existing localStorage value on mount", () => {
    localStorage.setItem("display:aws-prod:images", "grid");
    const { result } = renderHook(() => useDisplayMode("aws-prod", "images"));
    expect(result.current.mode).toBe("grid");
  });

  it("isolates per role+bucket", () => {
    const a = renderHook(() => useDisplayMode("aws-prod", "images"));
    act(() => a.result.current.setMode("grid"));

    const b = renderHook(() => useDisplayMode("r2-cdn", "static"));
    expect(b.result.current.mode).toBe("table"); // independent
  });
});
