import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen } from "@testing-library/react";
import { MantineProvider } from "@mantine/core";
import { Notifications } from "@mantine/notifications";
import { MemoryRouter } from "react-router-dom";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";

const usePasswordPolicyMock = vi.fn();
vi.mock("@/features/auth/hooks/usePasswordPolicy", () => ({
  usePasswordPolicy: () => usePasswordPolicyMock(),
}));
vi.mock("@/features/auth/hooks/useChangeMyPassword", () => ({
  useChangeMyPassword: () => ({ mutate: vi.fn(), mutateAsync: vi.fn(), isPending: false }),
}));

import { ChangePasswordPage } from "@/pages/ChangePasswordPage";

function renderPage() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <MantineProvider>
      <Notifications />
      <QueryClientProvider client={qc}>
        <MemoryRouter>
          <ChangePasswordPage />
        </MemoryRouter>
      </QueryClientProvider>
    </MantineProvider>,
  );
}

describe("ChangePasswordPage password-policy warning", () => {
  beforeEach(() => usePasswordPolicyMock.mockReset());

  it("renders an inline warning when the policy fetch fails", () => {
    usePasswordPolicyMock.mockReturnValue({ data: undefined, isError: true });
    renderPage();
    // Mantine Alert renders children in a <div> without splitting, but in case Mantine
    // internal markup splits the text, we assert each clause independently.
    expect(
      screen.getByText(/couldn't load password policy/i),
    ).toBeInTheDocument();
    expect(
      screen.getByText(/server will validate.*on save/i),
    ).toBeInTheDocument();
  });

  it("does NOT render the warning when the policy loads", () => {
    usePasswordPolicyMock.mockReturnValue({
      data: {
        password_min_length: 8,
        password_min_uppercase: 1,
        password_min_lowercase: 1,
        password_min_digits: 1,
        password_min_special: 0,
      },
      isError: false,
    });
    renderPage();
    expect(
      screen.queryByText(/couldn't load password policy/i),
    ).not.toBeInTheDocument();
  });
});
