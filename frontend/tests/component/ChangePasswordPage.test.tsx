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

import { changeMyPassword } from "@/features/auth/api/authApi";

function renderPage() {
  const qc = new QueryClient({ defaultOptions: { mutations: { retry: false } } });
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
  beforeEach(() => {
    vi.mocked(changeMyPassword).mockClear();
  });

  it("submits when fields are valid and confirm matches", async () => {
    renderPage();
    fireEvent.change(screen.getByLabelText(/current password/i), { target: { value: "oldpass" } });
    fireEvent.change(screen.getByLabelText(/^new password/i), { target: { value: "newpass1234" } });
    fireEvent.change(screen.getByLabelText(/confirm new password/i), { target: { value: "newpass1234" } });
    fireEvent.click(screen.getByRole("button", { name: /change password/i }));
    await waitFor(() =>
      expect(changeMyPassword).toHaveBeenCalledWith({
        current_password: "oldpass",
        new_password: "newpass1234",
      }),
    );
  });

  it("blocks submit when confirm does not match", async () => {
    renderPage();
    fireEvent.change(screen.getByLabelText(/current password/i), { target: { value: "oldpass" } });
    fireEvent.change(screen.getByLabelText(/^new password/i), { target: { value: "newpass1234" } });
    fireEvent.change(screen.getByLabelText(/confirm new password/i), { target: { value: "different" } });
    fireEvent.click(screen.getByRole("button", { name: /change password/i }));
    await waitFor(() => expect(screen.getByText(/does not match/i)).toBeInTheDocument());
    expect(changeMyPassword).not.toHaveBeenCalled();
  });

  it("blocks submit when new password is too short", async () => {
    renderPage();
    fireEvent.change(screen.getByLabelText(/current password/i), { target: { value: "oldpass" } });
    fireEvent.change(screen.getByLabelText(/^new password/i), { target: { value: "short" } });
    fireEvent.change(screen.getByLabelText(/confirm new password/i), { target: { value: "short" } });
    fireEvent.click(screen.getByRole("button", { name: /change password/i }));
    await waitFor(() => expect(screen.getByText(/8\+ characters/i)).toBeInTheDocument());
    expect(changeMyPassword).not.toHaveBeenCalled();
  });
});
