import "@testing-library/jest-dom/vitest";
import { notifyManager } from "@tanstack/react-query";

// TanStack Query batches observer notifications on a macrotask by default, so a
// state update triggered by an awaited fetchNextPage()/refetch() lands AFTER the
// surrounding act() flush — making hooks like useFiles.loadMore()/loadAll() look
// like they "didn't update" in tests even though the cache is correct. Flushing
// notifications synchronously in the test environment makes query state settle
// within the same act() scope. Test-only: production keeps the batched scheduler.
notifyManager.setScheduler((cb) => cb());

// Node 25 ships an experimental built-in localStorage that shadows jsdom's
// implementation. The built-in object has no getItem/setItem/clear methods.
// Replace it with a fully functional in-memory shim so tests can use localStorage.
if (
  typeof globalThis.localStorage === "undefined" ||
  typeof (globalThis.localStorage as Storage).getItem !== "function"
) {
  const store: Record<string, string> = {};
  Object.defineProperty(globalThis, "localStorage", {
    writable: true,
    configurable: true,
    value: {
      getItem: (key: string) => (key in store ? store[key] : null),
      setItem: (key: string, value: string) => {
        store[key] = String(value);
      },
      removeItem: (key: string) => {
        delete store[key];
      },
      clear: () => {
        Object.keys(store).forEach((k) => delete store[k]);
      },
      get length() {
        return Object.keys(store).length;
      },
      key: (index: number) => Object.keys(store)[index] ?? null,
    } satisfies Storage,
  });
}

// jsdom doesn't implement ResizeObserver, but Mantine's ScrollArea (used by
// Drawer/Modal/Popover) calls it. Stub a no-op shim so tests can render those.
if (typeof globalThis.ResizeObserver === "undefined") {
  class ResizeObserverShim {
    observe() {}
    unobserve() {}
    disconnect() {}
  }
  Object.defineProperty(globalThis, "ResizeObserver", {
    writable: true,
    configurable: true,
    value: ResizeObserverShim,
  });
}

// jsdom doesn't implement Element.scrollIntoView, but Mantine's Combobox/Select
// calls it asynchronously (via setTimeout) after option selection to scroll the
// chosen item into view. Without this shim, an unhandled TypeError fires AFTER
// the test passes, polluting the test report.
if (
  typeof Element !== "undefined" &&
  typeof Element.prototype.scrollIntoView !== "function"
) {
  Element.prototype.scrollIntoView = function () {};
}

// jsdom doesn't implement matchMedia, but Mantine + our CubeLogo (and many
// component-test-friendly libs) call it during render. Stub a no-op shim that
// always reports "doesn't match" so reduced-motion paths pick the animated branch.
if (typeof window !== "undefined" && !window.matchMedia) {
  Object.defineProperty(window, "matchMedia", {
    writable: true,
    value: (query: string) => ({
      matches: false,
      media: query,
      onchange: null,
      addEventListener: () => {},
      removeEventListener: () => {},
      addListener: () => {},
      removeListener: () => {},
      dispatchEvent: () => false,
    }),
  });
}
