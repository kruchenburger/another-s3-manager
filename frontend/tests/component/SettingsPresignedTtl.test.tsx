import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor, fireEvent } from "@testing-library/react";
import { MantineProvider } from "@mantine/core";
import { Notifications } from "@mantine/notifications";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import { SettingsPage } from "@/pages/admin/SettingsPage";

vi.mock("@/features/admin/api/adminApi", () => ({
  getConfig: vi.fn(),
  saveConfig: vi.fn(),
  exportConfig: vi.fn(),
}));
import {
  getConfig,
  saveConfig,
} from "@/features/admin/api/adminApi";

const BASE_CONFIG = {
  roles: [{ name: "Default", type: "default" as const }],
  default_role: "Default",
  enable_lazy_loading: true,
  max_file_size: 100 * 1024 * 1024,
  max_client_load: 10000,
  presigned_url_default_ttl: 3600,
  presigned_url_max_ttl: 604800,
  disable_deletion: false,
  auto_inline_extensions: [],
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
  const qc = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
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

describe("Settings — Presigned URLs", () => {
  beforeEach(() => {
    vi.mocked(getConfig).mockReset();
    vi.mocked(saveConfig).mockReset();
    vi.mocked(getConfig).mockResolvedValue(BASE_CONFIG);
  });

  it("renders default + maximum validity selects", async () => {
    renderPage();
    // Wait for config to load (form populates).
    // Mantine 9 Select renders its input as role="combobox" (ARIA-correct).
    await waitFor(() =>
      expect(
        screen.getByRole("combobox", { name: /default link validity/i }),
      ).toBeInTheDocument(),
    );
    expect(
      screen.getByRole("combobox", { name: /maximum link validity/i }),
    ).toBeInTheDocument();
  });

  it("blocks Save when default exceeds maximum", async () => {
    renderPage();

    // Wait for config to load
    await waitFor(() =>
      expect(
        screen.getByRole("combobox", { name: /default link validity/i }),
      ).toBeInTheDocument(),
    );

    // Mantine 9 Combobox renders options only while the dropdown is open (v8 kept
    // them pre-rendered in a hidden Popover). Both selects share option labels
    // ("7 days", "1 hour", …), so we open one dropdown at a time and pick from it
    // while it's the only listbox in the DOM — keeping the option labels unambiguous.

    // Default → "7 days" (fireEvent.click opens the Mantine 9 dropdown reliably in
    // jsdom; scope to role="option" so the *other* select's displayed value — which
    // is also "7 days" as text — doesn't collide with the option we want).
    fireEvent.click(
      screen.getByRole("combobox", { name: /default link validity/i }),
    );
    fireEvent.click(await screen.findByRole("option", { name: "7 days" }));

    // Maximum → "1 hour"
    fireEvent.click(
      screen.getByRole("combobox", { name: /maximum link validity/i }),
    );
    fireEvent.click(await screen.findByRole("option", { name: "1 hour" }));

    // Validation error must appear: "cannot exceed"
    await waitFor(() =>
      expect(screen.getByText(/cannot exceed/i)).toBeInTheDocument(),
    );

    // Save button must be disabled
    const saveBtn = screen.getAllByRole("button", { name: /save settings/i })[0]!;
    expect(saveBtn).toBeDisabled();
  });
});
