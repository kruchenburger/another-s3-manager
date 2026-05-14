import { render, screen } from "@testing-library/react";
import { MantineProvider } from "@mantine/core";
import { MemoryRouter } from "react-router-dom";
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { HomePage } from "@/pages/HomePage";

const navigateMock = vi.fn();

vi.mock("react-router-dom", async () => {
  const actual = await vi.importActual<typeof import("react-router-dom")>("react-router-dom");
  return {
    ...actual,
    useNavigate: () => navigateMock,
  };
});

const useMeMock = vi.fn();
vi.mock("@/features/auth/hooks/useMe", () => ({
  useMe: () => useMeMock(),
}));

function renderPage() {
  return render(
    <MantineProvider>
      <MemoryRouter basename="/v2" initialEntries={["/v2/"]}>
        <HomePage />
      </MemoryRouter>
    </MantineProvider>,
  );
}

describe("HomePage auto-open single role", () => {
  beforeEach(() => {
    navigateMock.mockReset();
    useMeMock.mockReset();
  });

  it("redirects to the only role when allowed_roles.length === 1", () => {
    useMeMock.mockReturnValue({ data: { allowed_roles: ["solo-role"] } });
    renderPage();
    expect(navigateMock).toHaveBeenCalledTimes(1);
    expect(navigateMock).toHaveBeenCalledWith("/r/solo-role", { replace: true });
  });

  it("redirects to allowed_roles[0] when there are multiple roles and no default_role", () => {
    // Behaviour changed in Phase 6a-4: multi-role users are now redirected to
    // allowed_roles[0] as a fallback; DefaultRolePicker in the header lets them switch.
    useMeMock.mockReturnValue({ data: { allowed_roles: ["r1", "r2"], default_role: null } });
    renderPage();
    expect(navigateMock).toHaveBeenCalledTimes(1);
    expect(navigateMock).toHaveBeenCalledWith("/r/r1", { replace: true });
  });

  it("does not redirect when allowed_roles is empty", () => {
    useMeMock.mockReturnValue({ data: { allowed_roles: [] } });
    renderPage();
    expect(navigateMock).not.toHaveBeenCalled();
    expect(screen.getByText(/pick a role to get started/i)).toBeInTheDocument();
  });

  it("does not redirect while me is loading", () => {
    useMeMock.mockReturnValue({ data: undefined });
    renderPage();
    expect(navigateMock).not.toHaveBeenCalled();
  });

  it("encodes role names with special characters", () => {
    useMeMock.mockReturnValue({ data: { allowed_roles: ["my role/v2"] } });
    renderPage();
    expect(navigateMock).toHaveBeenCalledWith("/r/my%20role%2Fv2", { replace: true });
  });

  it("does not redirect when stale cached me coexists with a fresh error", () => {
    // Race scenario: TanStack Query returns the previously-cached single role
    // while a concurrent refresh fails (e.g. cookie expired, or admin removed
    // this role server-side and the me query just got invalidated). The user
    // must NOT be silently redirected past the error path — the picker
    // (or upstream error UI) should show instead.
    useMeMock.mockReturnValue({
      data: { allowed_roles: ["stale-role"] },
      error: new Error("session expired"),
    });
    renderPage();
    expect(navigateMock).not.toHaveBeenCalled();
    // Don't blank-screen either — the picker text should still render so the
    // user has a fallback.
    expect(screen.getByText(/pick a role to get started/i)).toBeInTheDocument();
  });
});

describe("HomePage default_role redirect", () => {
  beforeEach(() => {
    navigateMock.mockReset();
    useMeMock.mockReset();
  });
  afterEach(() => vi.restoreAllMocks());

  it("redirects to the explicit default_role over allowed_roles[0]", () => {
    useMeMock.mockReturnValue({
      data: { allowed_roles: ["RoleA", "RoleB"], default_role: "RoleB" },
      error: null,
    });
    renderPage();
    expect(navigateMock).toHaveBeenCalledTimes(1);
    expect(navigateMock).toHaveBeenCalledWith("/r/RoleB", { replace: true });
  });

  it("redirects to allowed_roles[0] when default_role is null", () => {
    useMeMock.mockReturnValue({
      data: { allowed_roles: ["RoleA", "RoleB"], default_role: null },
      error: null,
    });
    renderPage();
    expect(navigateMock).toHaveBeenCalledTimes(1);
    expect(navigateMock).toHaveBeenCalledWith("/r/RoleA", { replace: true });
  });

  it("does NOT redirect when error is set (stale-data guard)", () => {
    useMeMock.mockReturnValue({
      data: { allowed_roles: ["RoleA", "RoleB"], default_role: "RoleB" },
      error: new Error("session expired"),
    });
    renderPage();
    expect(navigateMock).not.toHaveBeenCalled();
    expect(screen.getByText(/pick a role to get started/i)).toBeInTheDocument();
  });
});
