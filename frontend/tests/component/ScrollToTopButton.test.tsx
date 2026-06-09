import { render, screen, fireEvent } from "@testing-library/react";
import { MantineProvider } from "@mantine/core";
import { useRef } from "react";
import { vi, describe, it, expect, beforeEach } from "vitest";
import { ScrollToTopButton } from "@/components/ScrollToTopButton/ScrollToTopButton";

// A harness that owns a scrollable div and passes its ref to the button, the
// same way FileBrowser will.
function Harness({ scrollTop }: { scrollTop: number }) {
  const ref = useRef<HTMLDivElement>(null);
  // Reflect the desired scrollTop onto the element once mounted.
  if (ref.current) ref.current.scrollTop = scrollTop;
  return (
    <MantineProvider>
      <div ref={ref} data-testid="scroll" style={{ height: 100, overflow: "auto" }}>
        <div style={{ height: 2000 }} />
      </div>
      <ScrollToTopButton scrollRef={ref} />
    </MantineProvider>
  );
}

describe("ScrollToTopButton", () => {
  beforeEach(() => {
    // jsdom doesn't implement scrollTo on elements; stub it so the click handler
    // can call it without throwing.
    Element.prototype.scrollTo = vi.fn() as unknown as typeof Element.prototype.scrollTo;
  });

  it("is hidden at the top of the container", () => {
    render(<Harness scrollTop={0} />);
    // Manually dispatch a scroll event so the listener reads scrollTop=0.
    fireEvent.scroll(screen.getByTestId("scroll"));
    expect(
      screen.queryByRole("button", { name: /scroll to top/i }),
    ).not.toBeInTheDocument();
  });

  it("appears after scrolling the container past the threshold", async () => {
    render(<Harness scrollTop={500} />);
    const el = screen.getByTestId("scroll");
    el.scrollTop = 500;
    fireEvent.scroll(el);
    expect(
      await screen.findByRole("button", { name: /scroll to top/i }),
    ).toBeInTheDocument();
  });

  it("scrolls the container back to the top on click", async () => {
    render(<Harness scrollTop={500} />);
    const el = screen.getByTestId("scroll");
    el.scrollTop = 500;
    fireEvent.scroll(el);
    const btn = await screen.findByRole("button", { name: /scroll to top/i });
    fireEvent.click(btn);
    expect(el.scrollTo).toHaveBeenCalledWith({ top: 0, behavior: "smooth" });
  });
});
