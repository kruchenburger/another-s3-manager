import { render, screen, fireEvent } from "@testing-library/react";
import { MantineProvider } from "@mantine/core";
import { vi, describe, it, expect, beforeEach } from "vitest";

// useWindowScroll drives both visibility (scroll.y) and the scroll-to-top
// action. Mock it so the test controls the scroll position deterministically;
// keep every other @mantine/hooks export real (Mantine core consumes some).
const scrollToMock = vi.fn();
let mockScrollY = 0;
vi.mock("@mantine/hooks", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@mantine/hooks")>();
  return {
    ...actual,
    useWindowScroll: () => [{ x: 0, y: mockScrollY }, scrollToMock] as const,
  };
});

import { ScrollToTopButton } from "@/components/ScrollToTopButton/ScrollToTopButton";

function renderButton() {
  return render(
    <MantineProvider>
      <ScrollToTopButton />
    </MantineProvider>,
  );
}

describe("ScrollToTopButton", () => {
  beforeEach(() => {
    scrollToMock.mockReset();
    mockScrollY = 0;
  });

  it("is hidden at the top of the page", () => {
    mockScrollY = 0;
    renderButton();
    expect(
      screen.queryByRole("button", { name: /scroll to top/i }),
    ).not.toBeInTheDocument();
  });

  it("appears after scrolling past the threshold", () => {
    mockScrollY = 500;
    renderButton();
    expect(
      screen.getByRole("button", { name: /scroll to top/i }),
    ).toBeInTheDocument();
  });

  it("scrolls back to the top on click", () => {
    mockScrollY = 500;
    renderButton();
    fireEvent.click(screen.getByRole("button", { name: /scroll to top/i }));
    expect(scrollToMock).toHaveBeenCalledWith({ y: 0 });
  });
});
