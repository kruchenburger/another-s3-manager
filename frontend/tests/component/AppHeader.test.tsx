import { render, screen } from "@testing-library/react";
import { MantineProvider } from "@mantine/core";
import { MemoryRouter } from "react-router-dom";
import { describe, it, expect, vi } from "vitest";
import { AppHeader } from "@/components/AppShell/AppHeader";

vi.mock("@/features/auth/hooks/useMe", () => ({
  useMe: () => ({ data: { app_name: "Another S3 Manager" } }),
}));

vi.mock("@/components/AppShell/ThemeToggle", () => ({
  ThemeToggle: () => null,
}));
vi.mock("@/components/AppShell/UserMenu", () => ({
  UserMenu: () => null,
}));
vi.mock("@/components/AppShell/HelpButton", () => ({
  HelpButton: () => null,
}));
vi.mock("@/components/BurgerLogo/BurgerLogo", () => ({
  BurgerLogo: () => <span data-testid="burger-logo" />,
}));

function renderHeader() {
  return render(
    <MantineProvider>
      <MemoryRouter basename="/v2" initialEntries={["/v2/r/some-role"]}>
        <AppHeader navOpened={false} onNavToggle={vi.fn()} onOpenTour={vi.fn()} />
      </MemoryRouter>
    </MantineProvider>,
  );
}

describe("AppHeader brand link", () => {
  it("wraps the brand block (logo + title) in a link to home", () => {
    renderHeader();
    const link = screen.getByRole("link", { name: /go to home/i });
    expect(link).toBeInTheDocument();
    // With basename=/v2 and to="/", react-router renders href="/v2".
    expect(link.getAttribute("href")).toBe("/v2");
    expect(link.textContent).toContain("Another S3 Manager");
  });
});
