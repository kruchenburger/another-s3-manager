import { renderHook } from "@testing-library/react";
import { vi, describe, it, expect } from "vitest";
import { useNearEndAutoLoad } from "@/components/FileBrowser/useNearEndAutoLoad";

// Minimal fake virtualizer: only getVirtualItems is consumed by the hook.
function fakeVirtualizer(lastIndex: number) {
  return {
    getVirtualItems: () => [{ index: lastIndex }],
  } as unknown as import("@tanstack/react-virtual").Virtualizer<
    HTMLDivElement,
    Element
  >;
}

describe("useNearEndAutoLoad", () => {
  it("fires onLoadMore when the last virtual index reaches the end and enabled", () => {
    const onLoadMore = vi.fn();
    renderHook(() =>
      useNearEndAutoLoad(fakeVirtualizer(9), 10, true, onLoadMore),
    );
    expect(onLoadMore).toHaveBeenCalledTimes(1);
  });

  it("does not fire when disabled", () => {
    const onLoadMore = vi.fn();
    renderHook(() =>
      useNearEndAutoLoad(fakeVirtualizer(9), 10, false, onLoadMore),
    );
    expect(onLoadMore).not.toHaveBeenCalled();
  });

  it("does not fire when the window is far from the end", () => {
    const onLoadMore = vi.fn();
    renderHook(() =>
      useNearEndAutoLoad(fakeVirtualizer(3), 100, true, onLoadMore),
    );
    expect(onLoadMore).not.toHaveBeenCalled();
  });

  it("does not fire for an empty list", () => {
    const onLoadMore = vi.fn();
    renderHook(() =>
      useNearEndAutoLoad(fakeVirtualizer(0), 0, true, onLoadMore),
    );
    expect(onLoadMore).not.toHaveBeenCalled();
  });

  it("re-fires after the list grows and the window reaches the new end", () => {
    const onLoadMore = vi.fn();
    const { rerender } = renderHook(
      ({ last, count }) =>
        useNearEndAutoLoad(fakeVirtualizer(last), count, true, onLoadMore),
      { initialProps: { last: 9, count: 10 } },
    );
    expect(onLoadMore).toHaveBeenCalledTimes(1);
    // Window scrolls back up after the append: no new fire.
    rerender({ last: 12, count: 20 });
    expect(onLoadMore).toHaveBeenCalledTimes(1);
    // Window reaches the new end: fire again.
    rerender({ last: 19, count: 20 });
    expect(onLoadMore).toHaveBeenCalledTimes(2);
  });
});
