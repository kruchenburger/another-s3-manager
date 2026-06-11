import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
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
  items_per_page: 200,
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
    // Mantine v8 Select renders its input as role="textbox" in jsdom.
    await waitFor(() =>
      expect(
        screen.getByRole("textbox", { name: /default link validity/i }),
      ).toBeInTheDocument(),
    );
    expect(
      screen.getByRole("textbox", { name: /maximum link validity/i }),
    ).toBeInTheDocument();
  });

  it("blocks Save when default exceeds maximum", async () => {
    const user = userEvent.setup();
    renderPage();

    // Wait for config to load
    await waitFor(() =>
      expect(
        screen.getByRole("textbox", { name: /default link validity/i }),
      ).toBeInTheDocument(),
    );

    // Mantine v8 Select renders all options in the DOM (inside a hidden Popover)
    // even before the dropdown is opened — use { hidden: true } to find them
    // without requiring the dropdown to open in jsdom (see TtlPopover.test.tsx).
    //
    // Both selects have the same option labels ("7 days", "1 hour" etc.), so we
    // scope to each select's specific listbox. Mantine renders each Select with
    // a listbox whose aria-labelledby points to the label element. We look up the
    // label element by text, get its id, then find the listbox with that labelledby.

    // Helper: find a Select's hidden listbox by matching the label text
    function getSelectListbox(labelText: string): HTMLElement {
      // Find all <label> elements with this text
      const labels = Array.from(document.querySelectorAll("label")).filter(
        (el) => el.textContent?.toLowerCase().includes(labelText.toLowerCase()),
      );
      if (!labels.length) throw new Error(`Label "${labelText}" not found`);
      const labelId = labels[0]!.id;
      // Find the listbox that is aria-labelledby this label
      const listbox = document.querySelector(
        `[role="listbox"][aria-labelledby="${labelId}"]`,
      ) as HTMLElement | null;
      if (!listbox) throw new Error(`Listbox for label "${labelText}" not found`);
      return listbox;
    }

    // Click "7 days" in the Default select listbox (bypasses display:none via within)
    const defListbox = getSelectListbox("Default link validity");
    const sevenDaysOption = within(defListbox).getByRole("option", {
      name: "7 days",
      hidden: true,
    });
    await user.click(sevenDaysOption);

    // Click "1 hour" in the Maximum select listbox
    const maxListbox = getSelectListbox("Maximum link validity");
    const oneHourOption = within(maxListbox).getByRole("option", {
      name: "1 hour",
      hidden: true,
    });
    await user.click(oneHourOption);

    // Validation error must appear: "cannot exceed"
    await waitFor(() =>
      expect(screen.getByText(/cannot exceed/i)).toBeInTheDocument(),
    );

    // Save button must be disabled
    const saveBtn = screen.getAllByRole("button", { name: /save settings/i })[0]!;
    expect(saveBtn).toBeDisabled();
  });
});
