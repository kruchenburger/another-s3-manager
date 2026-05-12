import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen } from "@testing-library/react";
import { MantineProvider } from "@mantine/core";
import { Notifications } from "@mantine/notifications";
import { MemoryRouter } from "react-router-dom";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { ApiError } from "@/utils/apiError";

const useMyTokensMock = vi.fn();
vi.mock("@/features/tokens/hooks/useMyTokens", () => ({
  useMyTokens: () => useMyTokensMock(),
}));
vi.mock("@/features/tokens/hooks/useCreateToken", () => ({
  useCreateMyToken: () => ({ mutate: vi.fn(), isPending: false }),
}));
vi.mock("@/features/tokens/hooks/useDeleteToken", () => ({
  useDeleteMyToken: () => ({ mutateAsync: vi.fn(), isPending: false }),
}));
vi.mock("@/features/tokens/hooks/useUpdateToken", () => ({
  useUpdateMyToken: () => ({ mutateAsync: vi.fn(), isPending: false }),
}));

import { ApiTokensPage } from "@/pages/ApiTokensPage";

function renderPage() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <MantineProvider>
      <Notifications />
      <QueryClientProvider client={qc}>
        <MemoryRouter>
          <ApiTokensPage />
        </MemoryRouter>
      </QueryClientProvider>
    </MantineProvider>,
  );
}

describe("ApiTokensPage error rendering", () => {
  beforeEach(() => useMyTokensMock.mockReset());

  it("renders QueryErrorState when useMyTokens fails", () => {
    useMyTokensMock.mockReturnValue({
      data: undefined,
      isLoading: false,
      error: new ApiError(500, "Internal Server Error", {
        detail: { code: "INTERNAL", message: "Server error — see logs" },
      }),
    });
    renderPage();
    expect(screen.getByText(/couldn't load tokens/i)).toBeInTheDocument();
    expect(screen.getByText("Server error — see logs")).toBeInTheDocument();
    // The token table must NOT render when there is an error.
    expect(screen.queryByRole("table")).not.toBeInTheDocument();
  });

  it("renders the table normally when there is no error", () => {
    useMyTokensMock.mockReturnValue({
      data: { tokens: [], used: 0, limit: 5 },
      isLoading: false,
      error: null,
    });
    renderPage();
    expect(screen.queryByText(/couldn't load tokens/i)).not.toBeInTheDocument();
    expect(screen.getByText(/used 0 of 5 token slots/i)).toBeInTheDocument();
  });
});
