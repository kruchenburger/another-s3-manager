import "@testing-library/jest-dom/vitest";

// Node 25 ships an experimental built-in localStorage that shadows jsdom's
// implementation. The built-in object has no getItem/setItem/clear methods.
// Replace it with a fully functional in-memory shim so tests can use localStorage.
if (typeof globalThis.localStorage === "undefined" || typeof (globalThis.localStorage as Storage).getItem !== "function") {
  const store: Record<string, string> = {};
  Object.defineProperty(globalThis, "localStorage", {
    writable: true,
    configurable: true,
    value: {
      getItem: (key: string) => (key in store ? store[key] : null),
      setItem: (key: string, value: string) => { store[key] = String(value); },
      removeItem: (key: string) => { delete store[key]; },
      clear: () => { Object.keys(store).forEach((k) => delete store[k]); },
      get length() { return Object.keys(store).length; },
      key: (index: number) => Object.keys(store)[index] ?? null,
    } satisfies Storage,
  });
}

// jsdom doesn't implement matchMedia, but Mantine + our BurgerLogo (and many
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
