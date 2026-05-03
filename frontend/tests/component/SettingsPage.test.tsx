import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { MantineProvider } from "@mantine/core";
import { Notifications } from "@mantine/notifications";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import { SettingsPage } from "@/pages/admin/SettingsPage";

vi.mock("@/features/admin/api/adminApi", () => ({
  getConfig: vi.fn(),
  saveConfig: vi.fn(),
}));
import { getConfig, saveConfig } from "@/features/admin/api/adminApi";

const baseConfig = {
  roles: [
    { name: "Default", type: "default" as const },
    { name: "MinIO", type: "s3_compatible" as const },
  ],
  default_role: "Default",
  items_per_page: 200,
  enable_lazy_loading: true,
  max_file_size: 100 * 1024 * 1024,
  disable_deletion: false,
  auto_inline_extensions: [],
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
          <SettingsPage />
        </MemoryRouter>
      </MantineProvider>
    </QueryClientProvider>,
  );
}

describe("SettingsPage", () => {
  beforeEach(() => {
    vi.mocked(getConfig).mockReset();
    vi.mocked(saveConfig).mockReset();
  });

  it("renders typed fields populated from config", async () => {
    vi.mocked(getConfig).mockResolvedValue(baseConfig);
    renderPage();

    await waitFor(() =>
      expect(screen.getByLabelText("Items per page")).toBeInTheDocument(),
    );
    expect(screen.getByLabelText("Items per page")).toHaveValue("200");
    // Mantine Switch components have role="switch"; addressed by accessible name.
    expect(screen.getByRole("switch", { name: /disable deletion/i })).not.toBeChecked();
    expect(screen.getByRole("switch", { name: /enable lazy loading/i })).toBeChecked();
    // 100 MB = 100 * 1024 * 1024 bytes — should display as 100 in the MB input
    expect(screen.getByLabelText("Max upload file size (MB)")).toHaveValue("100");
  });

  it("shows the read-only banner and hides the Save button when config is read-only", async () => {
    vi.mocked(getConfig).mockResolvedValue({ ...baseConfig, is_read_only: true });
    renderPage();
    await waitFor(() =>
      expect(screen.getByText(/mounted read-only/i)).toBeInTheDocument(),
    );
    expect(screen.queryByRole("button", { name: /save settings/i })).not.toBeInTheDocument();
  });

  it("disables form inputs in read-only mode", async () => {
    vi.mocked(getConfig).mockResolvedValue({ ...baseConfig, is_read_only: true });
    renderPage();
    await waitFor(() =>
      expect(screen.getByLabelText("Items per page")).toBeDisabled(),
    );
    expect(screen.getByRole("switch", { name: /disable deletion/i })).toBeDisabled();
    expect(screen.getByRole("switch", { name: /enable lazy loading/i })).toBeDisabled();
    expect(screen.getByLabelText("Max upload file size (MB)")).toBeDisabled();
  });

  it("submits the form with the correct shape (MB → bytes conversion)", async () => {
    vi.mocked(getConfig).mockResolvedValue(baseConfig);
    vi.mocked(saveConfig).mockResolvedValue(undefined);
    renderPage();

    await waitFor(() =>
      expect(screen.getByRole("button", { name: /save settings/i })).toBeInTheDocument(),
    );
    fireEvent.click(screen.getByRole("button", { name: /save settings/i }));

    await waitFor(() => expect(saveConfig).toHaveBeenCalledTimes(1));
    const submitted = vi.mocked(saveConfig).mock.calls[0]![0];
    expect(submitted.items_per_page).toBe(200);
    expect(submitted.max_file_size).toBe(100 * 1024 * 1024);   // converted from MB
    expect(submitted.disable_deletion).toBe(false);
  });

  it("preserves original byte precision when max_file_size_mb is not edited", async () => {
    // 5 GB decimal — not MiB-aligned, would round-trip to 4998524928 if we naively multiply by MB
    const oddByteCount = 5_000_000_000;
    vi.mocked(getConfig).mockResolvedValue({ ...baseConfig, max_file_size: oddByteCount });
    vi.mocked(saveConfig).mockResolvedValue(undefined);
    renderPage();

    await waitFor(() =>
      expect(screen.getByRole("button", { name: /save settings/i })).toBeInTheDocument(),
    );
    // Don't touch the MB field — just submit
    fireEvent.click(screen.getByRole("button", { name: /save settings/i }));

    await waitFor(() => expect(saveConfig).toHaveBeenCalledTimes(1));
    const submitted = vi.mocked(saveConfig).mock.calls[0]![0];
    expect(submitted.max_file_size).toBe(oddByteCount);  // exact byte count preserved
  });

  it("renders error EmptyState when getConfig fails", async () => {
    vi.mocked(getConfig).mockRejectedValue(new Error("Server error"));
    renderPage();
    await waitFor(() =>
      expect(screen.getByText(/couldn't load settings/i)).toBeInTheDocument(),
    );
  });

  it("does NOT send derived fields (data_dir, current_role, is_read_only) on save", async () => {
    vi.mocked(getConfig).mockResolvedValue({
      ...baseConfig,
      data_dir: "/data",
      current_role: "Default",
      is_read_only: false,
    });
    vi.mocked(saveConfig).mockResolvedValue(undefined);
    renderPage();
    await waitFor(() =>
      expect(screen.getByRole("button", { name: /save settings/i })).toBeInTheDocument(),
    );
    fireEvent.click(screen.getByRole("button", { name: /save settings/i }));
    await waitFor(() => expect(saveConfig).toHaveBeenCalledTimes(1));
    const submitted = vi.mocked(saveConfig).mock.calls[0]![0] as unknown as Record<string, unknown>;
    expect("data_dir" in submitted).toBe(false);
    expect("current_role" in submitted).toBe(false);
    expect("is_read_only" in submitted).toBe(false);
  });

  it("renders the 5 password policy NumberInputs", async () => {
    vi.mocked(getConfig).mockResolvedValue(baseConfig);
    renderPage();
    await waitFor(() =>
      expect(screen.getByLabelText(/minimum length/i)).toBeInTheDocument(),
    );
    expect(screen.getByLabelText(/minimum uppercase letters/i)).toBeInTheDocument();
    expect(screen.getByLabelText(/minimum lowercase letters/i)).toBeInTheDocument();
    expect(screen.getByLabelText(/minimum digits/i)).toBeInTheDocument();
    expect(screen.getByLabelText(/minimum special characters/i)).toBeInTheDocument();
  });

  it("includes the policy fields when saving", async () => {
    vi.mocked(getConfig).mockResolvedValue({
      ...baseConfig,
      password_min_uppercase: 1,
    });
    vi.mocked(saveConfig).mockResolvedValue(undefined);
    renderPage();
    await waitFor(() =>
      expect(screen.getByLabelText(/minimum length/i)).toBeInTheDocument(),
    );
    // change min_length to 12
    const minLength = screen.getByLabelText(/minimum length/i);
    fireEvent.change(minLength, { target: { value: "12" } });
    fireEvent.click(screen.getByRole("button", { name: /save settings/i }));
    await waitFor(() => expect(saveConfig).toHaveBeenCalled());
    const sentConfig = vi.mocked(saveConfig).mock.calls[0]![0];
    expect(sentConfig.password_min_length).toBe(12);
    expect(sentConfig.password_min_uppercase).toBe(1);
  });
});
