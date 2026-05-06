import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, fireEvent, waitFor, within } from "@testing-library/react";
import { MantineProvider } from "@mantine/core";
import { Notifications } from "@mantine/notifications";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter, Routes, Route } from "react-router-dom";
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
  mcp_enabled: true,
  mcp_disable_writes: false,
  mcp_text_extensions: [],
  mcp_global_max_read_bytes: 10 * 1024 * 1024,
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

function renderAt(path: string) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <MantineProvider>
        <Notifications />
        <MemoryRouter initialEntries={[path]}>
          <Routes>
            <Route path="/admin/roles" element={<RolesPage />} />
            <Route path="/admin/roles/new" element={<RolesPage />} />
            <Route path="/admin/roles/:roleName" element={<RolesPage />} />
          </Routes>
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

  it("renders amber Badge for 0-bucket role and dimmed text for >0 buckets", async () => {
    vi.mocked(getConfig).mockResolvedValue(baseConfig);
    renderPage();

    await waitFor(() => expect(screen.getByText("Default")).toBeInTheDocument());

    // 0-bucket row: text lives inside a Mantine Badge (root element has class
    // matching /mantine-Badge-root/). The dimmed Text variant uses a <p> with
    // a different className family, so this distinguishes the two paths.
    const zeroBadge = screen.getByText("No buckets");
    expect(zeroBadge.closest("[class*='mantine-Badge-root']")).not.toBeNull();

    // 2-bucket row: text is a plain dimmed Text — should NOT be inside a Badge.
    const twoText = screen.getByText("2 buckets");
    expect(twoText.closest("[class*='mantine-Badge-root']")).toBeNull();
  });

  it("opens the create-role drawer when navigated to /admin/roles/new", async () => {
    vi.mocked(getConfig).mockResolvedValue(baseConfig);
    renderAt("/admin/roles/new");

    // Wait for the list to render — the drawer is mounted alongside it.
    await waitFor(() => expect(screen.getByText("Default")).toBeInTheDocument());

    // Drawer header reads "Create role" in create mode.
    expect(screen.getByText(/create role/i)).toBeInTheDocument();
    // Step 1 picker shows the AWS credential chain radio.
    expect(
      screen.getByRole("radio", { name: /AWS credential chain/i }),
    ).toBeInTheDocument();
  });

  it("opens the edit-role drawer pre-filled when navigated to /admin/roles/:name", async () => {
    vi.mocked(getConfig).mockResolvedValue(baseConfig);
    renderAt("/admin/roles/R2");

    await waitFor(() =>
      expect(screen.getByText(/edit role: R2/i)).toBeInTheDocument(),
    );

    const nameInput = screen.getByRole("textbox", { name: /^name/i });
    expect(nameInput).toHaveValue("R2");
    expect(nameInput).toBeDisabled();

    // Type-picker locked in edit mode — every radio disabled.
    const radios = screen.getAllByRole("radio");
    expect(radios.length).toBe(5);
    radios.forEach((r) => expect(r).toBeDisabled());
  });

  it("Cancel in the edit drawer navigates back to /admin/roles", async () => {
    vi.mocked(getConfig).mockResolvedValue(baseConfig);
    renderAt("/admin/roles/R2");

    await waitFor(() =>
      expect(screen.getByText(/edit role: R2/i)).toBeInTheDocument(),
    );

    fireEvent.click(screen.getByRole("button", { name: /cancel/i }));

    // Drawer closed via URL change → "Edit role: R2" title is gone.
    await waitFor(() =>
      expect(screen.queryByText(/edit role: R2/i)).not.toBeInTheDocument(),
    );
    // The list stays visible behind/after the closed drawer.
    expect(screen.getByText("Default")).toBeInTheDocument();
    expect(screen.getByText("R2")).toBeInTheDocument();
  });

  it("redirects to /admin/roles with a notification when the role does not exist", async () => {
    vi.mocked(getConfig).mockResolvedValue(baseConfig);
    renderAt("/admin/roles/Nonexistent");

    // Notification appears — Notifications harness renders messages into the DOM.
    await waitFor(
      () =>
        expect(
          screen.getByText(/role "Nonexistent" not found/i),
        ).toBeInTheDocument(),
      { timeout: 2000 },
    );

    // Drawer closed (no edit-title), list visible.
    expect(screen.queryByText(/edit role: Nonexistent/i)).not.toBeInTheDocument();
    expect(screen.getByText("R2")).toBeInTheDocument();
  });

  it("preserves the existing secret when Save is clicked without typing one", async () => {
    vi.mocked(getConfig).mockResolvedValue(baseConfig);
    vi.mocked(saveConfig).mockResolvedValue(undefined);
    renderAt("/admin/roles/R2");

    await waitFor(() =>
      expect(screen.getByText(/edit role: R2/i)).toBeInTheDocument(),
    );

    fireEvent.click(screen.getByRole("button", { name: /save changes/i }));

    await waitFor(() => expect(saveConfig).toHaveBeenCalledTimes(1));
    const submitted = vi.mocked(saveConfig).mock.calls[0]![0];
    const r2 = submitted.roles.find((r) => r.name === "R2");
    // Parent merge attaches the original secret because the drawer emitted "".
    expect(r2?.secret_access_key).toBe("S");
  });

  it("uses the new secret when one is typed in the edit drawer", async () => {
    vi.mocked(getConfig).mockResolvedValue(baseConfig);
    vi.mocked(saveConfig).mockResolvedValue(undefined);
    renderAt("/admin/roles/R2");

    await waitFor(() =>
      expect(screen.getByText(/edit role: R2/i)).toBeInTheDocument(),
    );

    fireEvent.change(screen.getByLabelText(/^secret access key/i), {
      target: { value: "NEWSECRET" },
    });
    fireEvent.click(screen.getByRole("button", { name: /save changes/i }));

    await waitFor(() => expect(saveConfig).toHaveBeenCalledTimes(1));
    const submitted = vi.mocked(saveConfig).mock.calls[0]![0];
    const r2 = submitted.roles.find((r) => r.name === "R2");
    expect(r2?.secret_access_key).toBe("NEWSECRET");
  });

  it("clicking the row Edit button navigates to /admin/roles/:name and opens the drawer", async () => {
    vi.mocked(getConfig).mockResolvedValue(baseConfig);
    renderAt("/admin/roles");

    await waitFor(() => expect(screen.getByText("R2")).toBeInTheDocument());
    fireEvent.click(screen.getByRole("button", { name: /edit R2/i }));

    await waitFor(() =>
      expect(screen.getByText(/edit role: R2/i)).toBeInTheDocument(),
    );
  });
});
