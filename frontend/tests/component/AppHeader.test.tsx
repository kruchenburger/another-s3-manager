import { render, screen } from "@testing-library/react";
import { MantineProvider } from "@mantine/core";
import { MemoryRouter } from "react-router-dom";
import { describe, it, expect, vi, beforeEach } from "vitest";
import { AppHeader } from "@/components/AppShell/AppHeader";
import { GITHUB_URL } from "@/constants/links";

const useMeMock = vi.fn();
const useAppInfoMock = vi.fn();

vi.mock("@/features/auth/hooks/useMe", () => ({
  useMe: () => useMeMock(),
}));
vi.mock("@/hooks/useAppInfo", () => ({
  useAppInfo: () => useAppInfoMock(),
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
    useAppInfoMock.mockReset();
    useMeMock.mockReturnValue({
      data: { app_name: "Another S3 Manager", is_admin: false },
    });
    useAppInfoMock.mockReturnValue({ data: undefined });
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
    useAppInfoMock.mockReset();
    useAppInfoMock.mockReturnValue({ data: undefined });
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

describe("AppHeader GitHub link", () => {
  beforeEach(() => {
    useMeMock.mockReset();
    useAppInfoMock.mockReset();
    useMeMock.mockReturnValue({
      data: { app_name: "Another S3 Manager", is_admin: false },
    });
    useAppInfoMock.mockReturnValue({ data: undefined });
  });

  it("renders an external link to the project repository", () => {
    renderHeader();
    const link = screen.getByRole("link", { name: /view source on github/i });
    expect(link).toBeInTheDocument();
    expect(link.getAttribute("href")).toBe(GITHUB_URL);
    expect(link.getAttribute("target")).toBe("_blank");
    expect(link.getAttribute("rel")).toBe("noopener noreferrer");
  });
});

describe("AppHeader version chip", () => {
  beforeEach(() => {
    useMeMock.mockReset();
    useAppInfoMock.mockReset();
    useMeMock.mockReturnValue({
      data: { app_name: "Another S3 Manager", is_admin: false },
    });
  });

  it("renders v<version> next to the brand title when app_version is set", () => {
    useAppInfoMock.mockReturnValue({
      data: {
        app_name: "Another S3 Manager",
        app_description: "x",
        app_version: "1.0.0",
      },
    });
    renderHeader();
    expect(screen.getByText(/^v1\.0\.0$/)).toBeInTheDocument();
  });

  it("does NOT render the chip when app_version is 'dev'", () => {
    useAppInfoMock.mockReturnValue({
      data: {
        app_name: "Another S3 Manager",
        app_description: "x",
        app_version: "dev",
      },
    });
    renderHeader();
    expect(screen.queryByText(/^vdev$/)).not.toBeInTheDocument();
  });

  it("does NOT render the chip when appInfo has not loaded yet", () => {
    useAppInfoMock.mockReturnValue({ data: undefined });
    renderHeader();
    expect(screen.queryByText(/^v/)).not.toBeInTheDocument();
  });

  it("renders the version chip OUTSIDE the brand home link", () => {
    // Regression guard: the chip used to live inside <Link to="/">, which
    // made clicking the version label navigate home (unintended UX).
    useAppInfoMock.mockReturnValue({
      data: {
        app_name: "Another S3 Manager",
        app_description: "x",
        app_version: "1.0.0",
      },
    });
    renderHeader();
    const link = screen.getByRole("link", { name: /go to home/i });
    const chip = screen.getByText(/^v1\.0\.0$/);
    // The chip should NOT be a descendant of the home link.
    expect(link.contains(chip)).toBe(false);
  });
});
