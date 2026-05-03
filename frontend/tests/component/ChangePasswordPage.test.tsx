import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { MantineProvider } from "@mantine/core";
import { Notifications } from "@mantine/notifications";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import { ChangePasswordPage } from "@/pages/ChangePasswordPage";

vi.mock("@/features/auth/api/authApi", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/features/auth/api/authApi")>();
  return { ...actual, changeMyPassword: vi.fn(async () => undefined) };
});

vi.mock("@/features/admin/api/adminApi", () => ({
  getConfig: vi.fn(async () => ({
    roles: [],
    items_per_page: 200,
    enable_lazy_loading: true,
    max_file_size: 100 * 1024 * 1024,
    disable_deletion: false,
    password_min_length: 8,
    password_min_uppercase: 1,
    password_min_lowercase: 1,
    password_min_digits: 1,
    password_min_special: 0,
  })),
}));

import { changeMyPassword } from "@/features/auth/api/authApi";
import { getConfig } from "@/features/admin/api/adminApi";

beforeEach(() => {
  vi.mocked(changeMyPassword).mockClear();
});

function renderPage() {
  const qc = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
  return render(
    <QueryClientProvider client={qc}>
      <MantineProvider>
        <Notifications />
        <MemoryRouter>
          <ChangePasswordPage />
        </MemoryRouter>
      </MantineProvider>
    </QueryClientProvider>,
  );
}

describe("ChangePasswordPage", () => {
  it("submits when fields are valid and policy is met", async () => {
    renderPage();
    // Wait for the policy to load — Save button is disabled until then.
    await waitFor(() =>
      expect(screen.getByRole("button", { name: /change password/i })).not.toBeDisabled(),
    );
    fireEvent.change(screen.getByLabelText(/current password/i), { target: { value: "OldPass1" } });
    fireEvent.change(screen.getByLabelText(/^new password/i), { target: { value: "NewPass456" } });
    fireEvent.change(screen.getByLabelText(/confirm new password/i), { target: { value: "NewPass456" } });
    fireEvent.click(screen.getByRole("button", { name: /change password/i }));
    await waitFor(() =>
      expect(changeMyPassword).toHaveBeenCalledWith({
        current_password: "OldPass1",
        new_password: "NewPass456",
      }),
    );
  });

  it("blocks submit when confirm does not match", async () => {
    renderPage();
    await waitFor(() =>
      expect(screen.getByRole("button", { name: /change password/i })).not.toBeDisabled(),
    );
    fireEvent.change(screen.getByLabelText(/current password/i), { target: { value: "OldPass1" } });
    fireEvent.change(screen.getByLabelText(/^new password/i), { target: { value: "NewPass456" } });
    fireEvent.change(screen.getByLabelText(/confirm new password/i), { target: { value: "DifferentPass1" } });
    fireEvent.click(screen.getByRole("button", { name: /change password/i }));
    await waitFor(() => expect(screen.getByText(/does not match/i)).toBeInTheDocument());
    expect(changeMyPassword).not.toHaveBeenCalled();
  });

  it("blocks submit when new password fails policy (missing uppercase)", async () => {
    renderPage();
    await waitFor(() =>
      expect(screen.getByRole("button", { name: /change password/i })).not.toBeDisabled(),
    );
    fireEvent.change(screen.getByLabelText(/current password/i), { target: { value: "OldPass1" } });
    fireEvent.change(screen.getByLabelText(/^new password/i), { target: { value: "weakpass1" } }); // no uppercase
    fireEvent.change(screen.getByLabelText(/confirm new password/i), { target: { value: "weakpass1" } });
    fireEvent.click(screen.getByRole("button", { name: /change password/i }));
    await waitFor(() => expect(screen.getByText(/password does not meet policy/i)).toBeInTheDocument());
    expect(changeMyPassword).not.toHaveBeenCalled();
  });

  it("renders the requirements checklist next to the New password field", async () => {
    renderPage();
    await waitFor(() => expect(screen.getByText(/at least 8 characters/i)).toBeInTheDocument());
    expect(screen.getByText(/at least 1 uppercase letter/i)).toBeInTheDocument();
    expect(screen.getByText(/at least 1 lowercase letter/i)).toBeInTheDocument();
    expect(screen.getByText(/at least 1 digit/i)).toBeInTheDocument();
  });

  it("unblocks submit when policy fetch fails (server is final source of truth)", async () => {
    vi.mocked(getConfig).mockRejectedValueOnce(new Error("network down"));
    renderPage();
    // Even without a policy, the user can submit and rely on backend 422 validation.
    await waitFor(() =>
      expect(screen.getByRole("button", { name: /change password/i })).not.toBeDisabled(),
    );
    // Checklist absent because policy is undefined
    expect(screen.queryByText(/at least \d+ character/i)).not.toBeInTheDocument();
  });
});
