import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen } from "@testing-library/react";
import { MantineProvider } from "@mantine/core";
import { MemoryRouter, Routes, Route } from "react-router-dom";
import { RequireFreshPassword } from "@/components/Auth/RequireFreshPassword";

const useMeMock = vi.fn();
vi.mock("@/features/auth/hooks/useMe", () => ({
  useMe: () => useMeMock(),
}));

function renderGuard(initialPath: string) {
  return render(
    <MantineProvider>
      <MemoryRouter initialEntries={[initialPath]}>
        <Routes>
          <Route element={<RequireFreshPassword />}>
            <Route path="/" element={<div data-testid="home">home</div>} />
            <Route path="/r/:roleId" element={<div data-testid="role">role</div>} />
            <Route path="/change-password" element={<div data-testid="change">change page</div>} />
          </Route>
        </Routes>
      </MemoryRouter>
    </MantineProvider>,
  );
}

describe("RequireFreshPassword", () => {
  beforeEach(() => vi.clearAllMocks());
  afterEach(() => vi.restoreAllMocks());

  it("redirects to /change-password when must_change_password is true", () => {
    useMeMock.mockReturnValue({
      data: { must_change_password: true, allowed_roles: [], default_role: null },
    });
    renderGuard("/");
    expect(screen.getByTestId("change")).toBeInTheDocument();
    expect(screen.queryByTestId("home")).not.toBeInTheDocument();
  });

  it("renders the protected route when must_change_password is false", () => {
    useMeMock.mockReturnValue({
      data: { must_change_password: false, allowed_roles: ["RoleA"], default_role: "RoleA" },
    });
    renderGuard("/");
    expect(screen.getByTestId("home")).toBeInTheDocument();
    expect(screen.queryByTestId("change")).not.toBeInTheDocument();
  });

  it("allows access to /change-password even when must_change_password is true", () => {
    useMeMock.mockReturnValue({
      data: { must_change_password: true, allowed_roles: [], default_role: null },
    });
    renderGuard("/change-password");
    expect(screen.getByTestId("change")).toBeInTheDocument();
  });
});
