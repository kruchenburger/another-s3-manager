import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { renderHook, act } from "@testing-library/react";
import { useAnimatedNumber } from "@/hooks/useAnimatedNumber";

/**
 * These tests drive requestAnimationFrame/performance.now manually instead of
 * using vi.useFakeTimers(): the hook schedules via rAF (not setTimeout), and the
 * regression below specifically needs to control the *relationship* between the
 * timestamp captured by performance.now() inside the effect and the timestamp
 * handed to the rAF callback — fake timers can't express "callback runs with an
 * earlier timestamp than what performance.now() returned a moment ago".
 */

// Pending-callback registry keyed by id, so cancelAnimationFrame can actually
// remove a callback (mirrors real browser semantics) instead of leaving it to
// fire later — a plain array queue would let "cancelled" frames leak through.
let rafCallbacks: Map<number, (now: number) => void>;
let rafId = 0;

function flushRaf(now: number) {
  const callbacks = Array.from(rafCallbacks.values());
  rafCallbacks.clear();
  callbacks.forEach((cb) => cb(now));
}

describe("useAnimatedNumber", () => {
  beforeEach(() => {
    rafCallbacks = new Map();
    rafId = 0;
    vi.stubGlobal("requestAnimationFrame", (cb: FrameRequestCallback) => {
      rafId += 1;
      rafCallbacks.set(rafId, cb as (now: number) => void);
      return rafId;
    });
    vi.stubGlobal("cancelAnimationFrame", (id: number) => {
      rafCallbacks.delete(id);
    });
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  it("does not animate on mount — initial render returns the initial value", () => {
    const { result } = renderHook(() => useAnimatedNumber(42));
    expect(result.current).toBe(42);
    // No rAF should have been scheduled for the mount itself.
    expect(rafCallbacks.size).toBe(0);
  });

  it("animates from the current value toward a new target and lands exactly on the target at t >= 1", () => {
    vi.spyOn(performance, "now").mockReturnValue(1000);
    const { result, rerender } = renderHook(({ value }) => useAnimatedNumber(value), {
      initialProps: { value: 50 },
    });
    expect(result.current).toBe(50);

    rerender({ value: 100 });
    expect(rafCallbacks.size).toBe(1);

    // Mid-animation frame: t = 0.5 (250ms of a 500ms duration).
    act(() => flushRaf(1250));
    expect(result.current).toBeGreaterThan(50);
    expect(result.current).toBeLessThan(100);

    // Final frame: t >= 1 (500ms elapsed) lands exactly on target.
    act(() => flushRaf(1500));
    expect(result.current).toBe(100);
    // t >= 1 stops scheduling further frames.
    expect(rafCallbacks.size).toBe(0);
  });

  it("snaps immediately under prefers-reduced-motion instead of animating", () => {
    window.matchMedia = vi.fn().mockReturnValue({ matches: true });
    const { result, rerender } = renderHook(({ value }) => useAnimatedNumber(value), {
      initialProps: { value: 10 },
    });
    rerender({ value: 20 });
    expect(result.current).toBe(20);
    // No rAF loop scheduled — the snap path returns before requestAnimationFrame.
    expect(rafCallbacks.size).toBe(0);
  });

  it("continues from the currently displayed value when the target changes mid-animation, rather than snapping to the old target", () => {
    vi.spyOn(performance, "now").mockReturnValue(1000);
    const { result, rerender } = renderHook(({ value }) => useAnimatedNumber(value), {
      initialProps: { value: 0 },
    });

    rerender({ value: 100 });
    act(() => flushRaf(1250)); // t = 0.5 of the first animation
    const midValue = result.current;
    expect(midValue).toBeGreaterThan(0);
    expect(midValue).toBeLessThan(100);

    // A new target arrives before the first animation finished.
    rerender({ value: 200 });
    // First frame of the new animation (t=0) must read exactly midValue —
    // proof it started FROM what was on screen, not from the stale target (100).
    act(() => flushRaf(1000));
    expect(result.current).toBe(midValue);
    expect(result.current).not.toBe(100);
  });

  it("cancels its pending frame on unmount", () => {
    vi.spyOn(performance, "now").mockReturnValue(1000);
    const cancelSpy = vi.fn();
    vi.stubGlobal("cancelAnimationFrame", cancelSpy);
    const { rerender, unmount } = renderHook(({ value }) => useAnimatedNumber(value), {
      initialProps: { value: 0 },
    });
    rerender({ value: 100 });
    expect(rafCallbacks.size).toBe(1);

    unmount();
    expect(cancelSpy).toHaveBeenCalledTimes(1);
  });

  it("REGRESSION: never goes negative across many restarts triggered by an early rAF timestamp (Load-all drain)", () => {
    // Real-world trigger: a rAF callback receives the FRAME's start timestamp,
    // which can precede the performance.now() captured a moment earlier inside
    // the effect — so `now - start` can be negative on the very first tick of
    // every restart. Each Load-all chunk arriving during a drain restarts the
    // animation from whatever is currently displayed, so an unclamped `t`
    // compounds across restarts instead of resetting: 5-unit chunks with a 5ms
    // early timestamp reproduce the reported divergence (verified offline: the
    // unfixed math goes negative by the 3rd restart and reaches -193 by the
    // 40th, mirroring the user's report of -2133+ escalating to -871665980+).
    let nowValue = 1000;
    vi.spyOn(performance, "now").mockImplementation(() => nowValue);

    const { result, rerender } = renderHook(({ value }) => useAnimatedNumber(value), {
      initialProps: { value: 0 },
    });

    let target = 0;
    for (let i = 0; i < 40; i += 1) {
      target += 5; // simulates a 5-object chunk arriving during "Load all"
      nowValue += 1;
      act(() => rerender({ value: target }));

      // The rAF callback fires with a timestamp from BEFORE `start` — the
      // exact condition that produced `now - start < 0` in production.
      const frameTimestamp = nowValue - 5;
      act(() => flushRaf(frameTimestamp));

      expect(result.current).toBeGreaterThanOrEqual(0);
    }

    expect(result.current).toBeGreaterThanOrEqual(0);
  });
});
