import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen } from "@testing-library/react";
import { MantineProvider } from "@mantine/core";
import { Notifications } from "@mantine/notifications";
import { MemoryRouter } from "react-router-dom";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { ApiError } from "@/utils/apiError";

const useAdminTokensMock = vi.fn();
const useAdminUsersMock = vi.fn();

vi.mock("@/features/tokens/hooks/useAdminTokens", () => ({
  useAdminTokens: () => useAdminTokensMock(),
}));
vi.mock("@/features/tokens/hooks/useCreateToken", () => ({
  useCreateAdminToken: () => ({ mutate: vi.fn(), isPending: false }),
}));
vi.mock("@/features/tokens/hooks/useDeleteToken", () => ({
  useDeleteAdminToken: () => ({ mutateAsync: vi.fn(), isPending: false }),
}));
vi.mock("@/features/tokens/hooks/useUpdateToken", () => ({
  useUpdateAdminToken: () => ({ mutateAsync: vi.fn(), isPending: false }),
}));
vi.mock("@/features/admin/hooks/useAdminUsers", () => ({
  useAdminUsers: () => useAdminUsersMock(),
}));

import { AdminApiTokensPage } from "@/pages/admin/AdminApiTokensPage";

function renderPage() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <MantineProvider>
      <Notifications />
      <QueryClientProvider client={qc}>
        <MemoryRouter>
          <AdminApiTokensPage />
        </MemoryRouter>
      </QueryClientProvider>
    </MantineProvider>,
  );
}

describe("AdminApiTokensPage error rendering", () => {
  beforeEach(() => {
    useAdminTokensMock.mockReset();
    useAdminUsersMock.mockReset();
  });

  it("renders the tokens-error when useAdminTokens fails", () => {
    useAdminTokensMock.mockReturnValue({
      data: undefined,
      isLoading: false,
      error: new ApiError(500, "Internal Server Error", {
        detail: { code: "INTERNAL", message: "Token DB unavailable" },
      }),
    });
    useAdminUsersMock.mockReturnValue({
      data: { users: [], available_roles: [] },
      isLoading: false,
      error: null,
    });
    renderPage();
    expect(screen.getByText(/couldn't load tokens/i)).toBeInTheDocument();
    expect(screen.getByText("Token DB unavailable")).toBeInTheDocument();
    expect(screen.queryByRole("table")).not.toBeInTheDocument();
  });

  it("renders the users-error when useAdminUsers fails (and tokens succeeded)", () => {
    useAdminTokensMock.mockReturnValue({
      data: { tokens: [] },
      isLoading: false,
      error: null,
    });
    useAdminUsersMock.mockReturnValue({
      data: undefined,
      isLoading: false,
      error: new ApiError(500, "Internal Server Error", {
        detail: { code: "INTERNAL", message: "Users service down" },
      }),
    });
    renderPage();
    expect(screen.getByText(/couldn't load users/i)).toBeInTheDocument();
    expect(screen.getByText("Users service down")).toBeInTheDocument();
  });

  it("renders the table when both queries succeed", () => {
    useAdminTokensMock.mockReturnValue({
      data: { tokens: [] },
      isLoading: false,
      error: null,
    });
    useAdminUsersMock.mockReturnValue({
      data: { users: [], available_roles: [] },
      isLoading: false,
      error: null,
    });
    renderPage();
    expect(screen.queryByText(/couldn't load/i)).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: /issue token on behalf of user/i })).toBeInTheDocument();
  });
});
