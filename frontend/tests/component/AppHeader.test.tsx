import { render, screen } from "@testing-library/react";
import { MantineProvider } from "@mantine/core";
import { MemoryRouter } from "react-router-dom";
import { describe, it, expect, vi, beforeEach } from "vitest";
import { AppHeader } from "@/components/AppShell/AppHeader";

const useMeMock = vi.fn();
vi.mock("@/features/auth/hooks/useMe", () => ({
  useMe: () => useMeMock(),
}));

vi.mock("@/components/AppShell/ThemeToggle", () => ({
  ThemeToggle: () => null,
}));
vi.mock("@/components/AppShell/UserMenu", () => ({
  UserMenu: () => null,
}));
vi.mock("@/components/AppShell/DefaultRolePicker", () => ({
  DefaultRolePicker: () => null,
}));
vi.mock("@/components/BurgerLogo/BurgerLogo", () => ({
  BurgerLogo: () => <span data-testid="burger-logo" />,
}));

function renderHeader() {
  return render(
    <MantineProvider>
      <MemoryRouter basename="/v2" initialEntries={["/v2/r/some-role"]}>
        <AppHeader navOpened={false} onNavToggle={vi.fn()} />
      </MemoryRouter>
    </MantineProvider>,
  );
}

describe("AppHeader brand link", () => {
  beforeEach(() => {
    useMeMock.mockReset();
    useMeMock.mockReturnValue({
      data: { app_name: "Another S3 Manager", is_admin: false },
    });
  });

  it("wraps the brand block (logo + title) in a link to home", () => {
    renderHeader();
    const link = screen.getByRole("link", { name: /go to home/i });
    expect(link).toBeInTheDocument();
    // With basename=/v2 and to="/", react-router renders href="/v2".
    expect(link.getAttribute("href")).toBe("/v2");
    expect(link.textContent).toContain("Another S3 Manager");
  });
});

describe("AppHeader admin shortcut", () => {
  beforeEach(() => {
    useMeMock.mockReset();
  });

  it("does NOT render the admin button for non-admins", () => {
    useMeMock.mockReturnValue({
      data: { app_name: "Another S3 Manager", is_admin: false },
    });
    renderHeader();
    expect(
      screen.queryByRole("button", { name: /open admin console/i }),
    ).not.toBeInTheDocument();
  });

  it("renders the admin button for admins", () => {
    useMeMock.mockReturnValue({
      data: { app_name: "Another S3 Manager", is_admin: true },
    });
    renderHeader();
    expect(
      screen.getByRole("button", { name: /open admin console/i }),
    ).toBeInTheDocument();
  });
});
