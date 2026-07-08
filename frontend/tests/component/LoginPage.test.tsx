import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import { MantineProvider } from "@mantine/core";
import { MemoryRouter, Routes, Route } from "react-router-dom";
import { LoginPage } from "@/pages/LoginPage/LoginPage";
import { GITHUB_URL } from "@/constants/links";

const useAppInfoMock = vi.fn();
const useMeMock = vi.fn();
const useLoginMock = vi.fn();

vi.mock("@/hooks/useAppInfo", () => ({
  useAppInfo: () => useAppInfoMock(),
}));
vi.mock("@/features/auth/hooks/useMe", () => ({
  useMe: () => useMeMock(),
}));
vi.mock("@/features/auth/hooks/useLogin", () => ({
  useLogin: () => useLoginMock(),
}));
vi.mock("@/components/CubeLogo/CubeLogo", () => ({
  CubeLogo: () => <span data-testid="cube-logo" />,
}));

function renderLogin() {
  return render(
    <MantineProvider>
      <MemoryRouter basename="/v2" initialEntries={["/v2/login"]}>
        <LoginPage />
      </MemoryRouter>
    </MantineProvider>,
  );
}

describe("LoginPage parity additions", () => {
  beforeEach(() => {
    useAppInfoMock.mockReset();
    useMeMock.mockReset();
    useLoginMock.mockReset();
    useMeMock.mockReturnValue({ data: undefined });
    useLoginMock.mockReturnValue({
      mutate: vi.fn(),
      isPending: false,
      isError: false,
    });
    useAppInfoMock.mockReturnValue({ data: undefined });
  });

  it("renders the GitHub link in the footer band", () => {
    renderLogin();
    const link = screen.getByRole("link", { name: /source on github/i });
    expect(link).toHaveAttribute("href", GITHUB_URL);
    expect(link).toHaveAttribute("target", "_blank");
    expect(link).toHaveAttribute("rel", "noopener noreferrer");
  });

  it("does NOT render app_description as a tagline on login", () => {
    // The earlier round briefly added a tagline under the heading;
    // user rejected it — app name is self-explanatory and the extra
    // line of grey text was visual noise. app_description stays in
    // the backend response for tooltip/about uses, but the login
    // surface keeps the bare title.
    useAppInfoMock.mockReturnValue({
      data: {
        app_name: "Another S3 Manager",
        app_description: "Some description",
        app_version: "1.0.0",
      },
    });
    renderLogin();
    expect(screen.queryByText(/some description/i)).not.toBeInTheDocument();
  });

  it("renders the version next to the GitHub link in the footer", () => {
    // Reversal of the earlier "no version on login" rule: user wanted the
    // footer to match the design mockup, which shows "v1.0.0 · GitHub
    // Source" together. Version only renders when app_version is set so
    // a dev build (where the value may be missing) keeps the footer
    // looking clean.
    useAppInfoMock.mockReturnValue({
      data: {
        app_name: "Another S3 Manager",
        app_description: "x",
        app_version: "1.0.0",
      },
    });
    renderLogin();
    expect(screen.getByText(/^v1\.0\.0$/)).toBeInTheDocument();
  });

  it("renders the GitHub link regardless of app_version (including dev)", () => {
    useAppInfoMock.mockReturnValue({
      data: {
        app_name: "Another S3 Manager",
        app_description: "x",
        app_version: "dev",
      },
    });
    renderLogin();
    expect(
      screen.getByRole("link", { name: /source on github/i }),
    ).toBeInTheDocument();
  });

  it("uses fallback app name when appInfo is not yet loaded", () => {
    renderLogin();
    expect(screen.getByText(/another s3 manager/i)).toBeInTheDocument();
  });

  // ---- expired-session redirect-loop guard ----

  function renderWithRoutes() {
    return render(
      <MantineProvider>
        <MemoryRouter initialEntries={[{ pathname: "/login", state: { from: "/r/foo" } }]}>
          <Routes>
            <Route path="/login" element={<LoginPage />} />
            <Route path="/r/foo" element={<div>APP PAGE</div>} />
            <Route path="/" element={<div>HOME PAGE</div>} />
          </Routes>
        </MemoryRouter>
      </MantineProvider>,
    );
  }

  it("bounces to the origin route when the session is valid (isSuccess)", async () => {
    useMeMock.mockReturnValue({ data: { username: "admin" }, isSuccess: true });
    renderWithRoutes();
    // Valid session → navigate to state.from (/r/foo); login form gone.
    await waitFor(() => expect(screen.getByText("APP PAGE")).toBeInTheDocument());
    expect(screen.queryByRole("button", { name: "Login" })).not.toBeInTheDocument();
  });

  it("does NOT redirect when a stale me lingers but the session errored (no loop)", async () => {
    // Expired session: /api/me keeps last-good data while the refetch 401s.
    // isSuccess=false must keep us on /login instead of bouncing back into the
    // app (which would ping-pong AuthGuard <-> LoginPage forever).
    useMeMock.mockReturnValue({
      data: { username: "admin" },
      isSuccess: false,
      isError: true,
    });
    renderWithRoutes();
    // Give the effect a tick; the login form must remain and no navigation.
    await Promise.resolve();
    expect(screen.getByRole("button", { name: "Login" })).toBeInTheDocument();
    expect(screen.queryByText("APP PAGE")).not.toBeInTheDocument();
    expect(screen.queryByText("HOME PAGE")).not.toBeInTheDocument();
  });
});
