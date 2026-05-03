import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, fireEvent, waitFor, within } from "@testing-library/react";
import { MantineProvider } from "@mantine/core";
import { Notifications } from "@mantine/notifications";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import { RolesPage } from "@/pages/admin/RolesPage";

vi.mock("@/features/admin/api/adminApi", () => ({
  getConfig: vi.fn(),
  saveConfig: vi.fn(),
}));
import { getConfig, saveConfig } from "@/features/admin/api/adminApi";

const baseRole = {
  name: "Default",
  type: "default" as const,
  description: "",
  allowed_buckets: [],
};
const r2Role = {
  name: "R2",
  type: "s3_compatible" as const,
  description: "Cloudflare R2 prod",
  allowed_buckets: ["bucket-a", "bucket-b"],
  endpoint_url: "https://x.r2.cloudflarestorage.com",
  access_key_id: "K",
  secret_access_key: "S",
  region: "auto",
};
const baseConfig = {
  roles: [baseRole, r2Role],
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
};

function renderPage() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <MantineProvider>
        <Notifications />
        <MemoryRouter>
          <RolesPage />
        </MemoryRouter>
      </MantineProvider>
    </QueryClientProvider>,
  );
}

describe("RolesPage", () => {
  beforeEach(() => {
    vi.mocked(getConfig).mockReset();
    vi.mocked(saveConfig).mockReset();
  });

  it("renders roles in a table with name, type badge, bucket count, description", async () => {
    vi.mocked(getConfig).mockResolvedValue(baseConfig);
    renderPage();

    await waitFor(() => expect(screen.getByText("Default")).toBeInTheDocument());
    expect(screen.getByText("R2")).toBeInTheDocument();
    // Type badges
    expect(screen.getByText("default")).toBeInTheDocument();
    expect(screen.getByText("s3_compatible")).toBeInTheDocument();
    // Bucket count for R2 (2 buckets)
    expect(screen.getByText("2 buckets")).toBeInTheDocument();
    // Description for R2
    expect(screen.getByText("Cloudflare R2 prod")).toBeInTheDocument();
  });

  it("shows EmptyState with Add role CTA when there are no roles", async () => {
    vi.mocked(getConfig).mockResolvedValue({ ...baseConfig, roles: [] });
    renderPage();

    await waitFor(() => expect(screen.getByText(/no roles defined/i)).toBeInTheDocument());
    expect(screen.getByRole("button", { name: /add role/i })).toBeInTheDocument();
  });

  it("hides Add role CTA in EmptyState when read-only", async () => {
    vi.mocked(getConfig).mockResolvedValue({ ...baseConfig, roles: [], is_read_only: true });
    renderPage();
    await waitFor(() => expect(screen.getByText(/no roles defined/i)).toBeInTheDocument());
    expect(screen.queryByRole("button", { name: /add role/i })).not.toBeInTheDocument();
  });

  it("disables Edit and Delete buttons + Add role when read-only", async () => {
    vi.mocked(getConfig).mockResolvedValue({ ...baseConfig, is_read_only: true });
    renderPage();

    await waitFor(() => expect(screen.getByText("Default")).toBeInTheDocument());
    expect(screen.getByRole("button", { name: /add role/i })).toBeDisabled();
    expect(screen.getByRole("button", { name: /edit Default/i })).toBeDisabled();
    expect(screen.getByRole("button", { name: /delete Default/i })).toBeDisabled();
  });

  it("deletes a role through ConfirmDeleteModal", async () => {
    vi.mocked(getConfig).mockResolvedValue(baseConfig);
    vi.mocked(saveConfig).mockResolvedValue(undefined);
    renderPage();

    await waitFor(() => expect(screen.getByText("R2")).toBeInTheDocument());
    fireEvent.click(screen.getByRole("button", { name: /delete R2/i }));

    // ConfirmDeleteModal opens — match its title (not generic /delete/i which
    // also matches the per-row Delete button + "...This cannot be undone." copy).
    await waitFor(() =>
      expect(screen.getByText(/confirm deletion/i)).toBeInTheDocument(),
    );
    const dialog = screen.getByRole("dialog");
    fireEvent.click(within(dialog).getByRole("button", { name: /^delete$/i }));

    await waitFor(() => expect(saveConfig).toHaveBeenCalledTimes(1));
    const submitted = vi.mocked(saveConfig).mock.calls[0]![0];
    // R2 removed from roles, Default still there
    expect(submitted.roles).toHaveLength(1);
    expect(submitted.roles[0]!.name).toBe("Default");
  });

  it("renders error EmptyState when getConfig fails", async () => {
    vi.mocked(getConfig).mockRejectedValue(new Error("boom"));
    renderPage();
    await waitFor(() => expect(screen.getByText(/couldn't load roles/i)).toBeInTheDocument());
  });
});
