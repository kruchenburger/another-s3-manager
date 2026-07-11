import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { MantineProvider } from "@mantine/core";
import { Notifications } from "@mantine/notifications";
import { MemoryRouter } from "react-router-dom";

const navigateMock = vi.fn();
vi.mock("react-router-dom", async () => {
  const actual = await vi.importActual<typeof import("react-router-dom")>("react-router-dom");
  return { ...actual, useNavigate: () => navigateMock };
});

vi.mock("@/features/auth/hooks/useMe", () => ({
  useMe: () => ({ data: { username: "alice", is_admin: false } }),
}));

const logoutMutateMock = vi.fn();
vi.mock("@/features/auth/hooks/useLogout", () => ({
  useLogout: () => ({ mutate: logoutMutateMock, isPending: false }),
}));

import { UserMenu } from "@/components/AppShell/UserMenu";

function renderMenu() {
  return render(
    <MantineProvider>
      <Notifications />
      <MemoryRouter>
        <UserMenu />
      </MemoryRouter>
    </MantineProvider>,
  );
}

describe("UserMenu logout", () => {
  beforeEach(() => {
    navigateMock.mockReset();
    logoutMutateMock.mockReset();
  });

  it("navigates to /login on successful logout", async () => {
    logoutMutateMock.mockImplementation((_arg, opts) => {
      opts?.onSuccess?.();
    });
    renderMenu();
    fireEvent.click(screen.getByRole("button", { name: /user menu/i }));
    fireEvent.click(await screen.findByRole("menuitem", { name: /sign out/i }));
    await waitFor(() => expect(navigateMock).toHaveBeenCalledWith("/login", { replace: true }));
  });

  it("does NOT navigate on logout failure and shows a red toast", async () => {
    logoutMutateMock.mockImplementation((_arg, opts) => {
      opts?.onError?.(new Error("network down"));
    });
    renderMenu();
    fireEvent.click(screen.getByRole("button", { name: /user menu/i }));
    fireEvent.click(await screen.findByRole("menuitem", { name: /sign out/i }));
    // Mantine renders notification title and message in separate DOM nodes,
    // so we assert each independently.
    await waitFor(() =>
      expect(screen.getByText(/couldn't sign out/i)).toBeInTheDocument(),
    );
    expect(screen.getByText(/close the tab manually/i)).toBeInTheDocument();
    expect(navigateMock).not.toHaveBeenCalled();
  });
});
