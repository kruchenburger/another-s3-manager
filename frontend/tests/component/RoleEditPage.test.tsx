import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { MantineProvider } from "@mantine/core";
import { Notifications } from "@mantine/notifications";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter, Routes, Route } from "react-router-dom";
import { RoleEditPage } from "@/pages/admin/RoleEditPage";

vi.mock("@/features/admin/api/adminApi", () => ({
  getConfig: vi.fn(),
  saveConfig: vi.fn(),
}));
import { getConfig, saveConfig } from "@/features/admin/api/adminApi";

const r2Role = {
  name: "R2",
  type: "s3_compatible" as const,
  description: "Cloudflare R2 prod",
  endpoint_url: "https://x.r2.cloudflarestorage.com",
  access_key_id: "K",
  secret_access_key: "ORIGINAL_SECRET",
  region: "auto",
  allowed_buckets: ["bucket-a"],
};
const baseConfig = {
  roles: [r2Role],
  items_per_page: 200,
  enable_lazy_loading: true,
  max_file_size: 100 * 1024 * 1024,
  disable_deletion: false,
  is_read_only: false,
  password_min_length: 8,
  password_min_uppercase: 0,
  password_min_lowercase: 0,
  password_min_digits: 0,
  password_min_special: 0,
  mcp_enabled: true,
  mcp_disable_writes: false,
  mcp_text_extensions: [],
  mcp_global_max_read_bytes: 10 * 1024 * 1024,
};

function renderEdit(roleName: string) {
  const qc = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
  return render(
    <QueryClientProvider client={qc}>
      <MantineProvider>
        <Notifications />
        <MemoryRouter initialEntries={[`/admin/roles/${encodeURIComponent(roleName)}`]}>
          <Routes>
            <Route path="/admin/roles/:roleName" element={<RoleEditPage />} />
            <Route path="/admin/roles" element={<div>Roles list</div>} />
          </Routes>
        </MemoryRouter>
      </MantineProvider>
    </QueryClientProvider>,
  );
}

describe("RoleEditPage", () => {
  beforeEach(() => {
    vi.mocked(getConfig).mockReset();
    vi.mocked(saveConfig).mockReset();
  });

  it("preserves the existing secret_access_key when the user submits without entering a new one", async () => {
    vi.mocked(getConfig).mockResolvedValue(baseConfig);
    vi.mocked(saveConfig).mockResolvedValue(undefined);
    renderEdit("R2");

    // Wait for the form to populate from the loaded config
    await waitFor(() =>
      expect(screen.getByText(/edit role: r2/i)).toBeInTheDocument(),
    );

    // Submit the form without touching any field
    fireEvent.click(screen.getByRole("button", { name: /save changes/i }));

    await waitFor(() => expect(saveConfig).toHaveBeenCalledTimes(1));
    const submitted = vi.mocked(saveConfig).mock.calls[0]![0];
    const savedR2 = submitted.roles.find((r) => r.name === "R2");
    expect(savedR2).toBeDefined();
    // The original secret must round-trip — NOT replaced with "" from the form's empty input
    expect(savedR2!.secret_access_key).toBe("ORIGINAL_SECRET");
  });

  it("redirects to /admin/roles with a notification when the role doesn't exist", async () => {
    vi.mocked(getConfig).mockResolvedValue(baseConfig);
    renderEdit("Nonexistent");

    // Should land on the list (rendered via Routes fallback)
    await waitFor(() =>
      expect(screen.getByText(/roles list/i)).toBeInTheDocument(),
    );
    // And show the not-found notification
    await waitFor(() =>
      expect(screen.getByText(/role "nonexistent" not found/i)).toBeInTheDocument(),
    );
  });

  it("disables Save button in read-only mode", async () => {
    vi.mocked(getConfig).mockResolvedValue({ ...baseConfig, is_read_only: true });
    renderEdit("R2");

    await waitFor(() =>
      expect(screen.getByText(/edit role: r2/i)).toBeInTheDocument(),
    );
    expect(screen.getByRole("button", { name: /save changes/i })).toBeDisabled();
  });

  it("renders the friendly RoleTypePicker with the role's type and every radio disabled", async () => {
    vi.mocked(getConfig).mockResolvedValue(baseConfig);
    renderEdit("R2");

    await waitFor(() =>
      expect(screen.getByText(/edit role: r2/i)).toBeInTheDocument(),
    );

    // RoleTypePicker friendly labels render
    expect(screen.getByText(/Other S3-compatible service/i)).toBeInTheDocument();
    expect(screen.getByText(/AWS credential chain/i)).toBeInTheDocument();

    // All 5 radios are present and ALL disabled (type cannot change in edit mode)
    const radios = screen.getAllByRole("radio");
    expect(radios.length).toBe(5);
    radios.forEach((r) => expect(r).toBeDisabled());

    // The role's actual type (s3_compatible) is the selected one
    const r2Radio = radios.find((r) => (r as HTMLInputElement).value === "s3_compatible");
    expect(r2Radio).toBeDefined();
    expect((r2Radio as HTMLInputElement).checked).toBe(true);
  });

  it("disables every input including the picker when read-only", async () => {
    vi.mocked(getConfig).mockResolvedValue({ ...baseConfig, is_read_only: true });
    renderEdit("R2");

    await waitFor(() =>
      expect(screen.getByText(/edit role: r2/i)).toBeInTheDocument(),
    );

    // Picker disabled
    const radios = screen.getAllByRole("radio");
    radios.forEach((r) => expect(r).toBeDisabled());

    // A representative credential field disabled
    expect(screen.getByRole("textbox", { name: /^access key id/i })).toBeDisabled();
  });
});
