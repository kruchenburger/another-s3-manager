import "@testing-library/jest-dom/vitest";

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
