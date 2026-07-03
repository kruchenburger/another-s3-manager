import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { MantineProvider } from "@mantine/core";
import { Notifications, notifications } from "@mantine/notifications";
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
  exportConfig,
} from "@/features/admin/api/adminApi";

const baseConfig = {
  roles: [
    { name: "Default", type: "default" as const },
    { name: "MinIO", type: "s3_compatible" as const },
  ],
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

/** The Save button lives in the page-level sticky footer (outside the
 *  Tabs.Panel subtree), so there's exactly one such button per page. The
 *  helper uses `getAllByRole(...)[0]` rather than `getByRole(...)` so that
 *  the read-only path (where the footer is unmounted and no Save button
 *  exists) can use `queryAllByRole(...)` and assert length 0 without
 *  ambiguity. */
function clickSaveSettings() {
  const buttons = screen.getAllByRole("button", { name: /save settings/i });
  fireEvent.click(buttons[0]!);
}

async function waitForSaveButton() {
  await waitFor(() =>
    expect(
      screen.getAllByRole("button", { name: /save settings/i }).length,
    ).toBeGreaterThan(0),
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
      expect(screen.getByLabelText("Max client load")).toBeInTheDocument(),
    );
    expect(screen.getByLabelText("Max client load")).toHaveValue("10000");
    // Mantine Switch components have role="switch"; addressed by accessible name.
    expect(
      screen.getByRole("switch", { name: /disable deletion/i }),
    ).not.toBeChecked();
    expect(
      screen.getByRole("switch", { name: /enable lazy loading/i }),
    ).toBeChecked();
    // 100 MB = 100 * 1024 * 1024 bytes — should display as 100 in the MB input
    expect(screen.getByLabelText("Max upload file size (MB)")).toHaveValue(
      "100",
    );
  });

  it("shows the read-only banner and hides the Save button when config is read-only", async () => {
    vi.mocked(getConfig).mockResolvedValue({
      ...baseConfig,
      is_read_only: true,
    });
    renderPage();
    await waitFor(() =>
      expect(screen.getByText(/mounted read-only/i)).toBeInTheDocument(),
    );
    // The entire sticky Save bar is unmounted in read-only mode (no
    // editing → no need for Save/Discard at all), so the page should
    // contain zero buttons with the name.
    expect(
      screen.queryAllByRole("button", { name: /save settings/i }),
    ).toHaveLength(0);
  });

  it("disables form inputs in read-only mode", async () => {
    vi.mocked(getConfig).mockResolvedValue({
      ...baseConfig,
      is_read_only: true,
    });
    renderPage();
    await waitFor(() =>
      expect(screen.getByLabelText("Max client load")).toBeDisabled(),
    );
    expect(
      screen.getByRole("switch", { name: /disable deletion/i }),
    ).toBeDisabled();
    expect(
      screen.getByRole("switch", { name: /enable lazy loading/i }),
    ).toBeDisabled();
    expect(screen.getByLabelText("Max upload file size (MB)")).toBeDisabled();
  });

  it("submits the form with the correct shape (MB → bytes conversion)", async () => {
    vi.mocked(getConfig).mockResolvedValue(baseConfig);
    vi.mocked(saveConfig).mockResolvedValue(undefined);
    renderPage();

    await waitForSaveButton();
    // Save is disabled until something is dirty (matches standard form UX).
    // Bump max_client_load to enable Save without changing the MB field —
    // that lets us verify the byte-precision-preserved path on max_file_size.
    fireEvent.change(screen.getByLabelText("Max client load"), {
      target: { value: "300" },
    });
    clickSaveSettings();

    await waitFor(() => expect(saveConfig).toHaveBeenCalledTimes(1));
    const submitted = vi.mocked(saveConfig).mock.calls[0]![0];
    expect(submitted.max_client_load).toBe(300);
    expect(submitted.max_file_size).toBe(100 * 1024 * 1024); // preserved from original
    expect(submitted.disable_deletion).toBe(false);
  });

  it("preserves original byte precision when max_file_size_mb is not edited", async () => {
    // 5 GB decimal — not MiB-aligned, would round-trip to 4998524928 if we naively multiply by MB
    const oddByteCount = 5_000_000_000;
    vi.mocked(getConfig).mockResolvedValue({
      ...baseConfig,
      max_file_size: oddByteCount,
    });
    vi.mocked(saveConfig).mockResolvedValue(undefined);
    renderPage();

    await waitForSaveButton();
    // Dirty an UNRELATED field so Save is enabled. The MB field must stay
    // untouched — that's what this test is verifying. max_client_load lives
    // in the General tab too, but its dirty state only affects that one
    // field; max_file_size_mb stays clean and triggers the byte-preserve path.
    fireEvent.change(screen.getByLabelText("Max client load"), {
      target: { value: "300" },
    });
    clickSaveSettings();

    await waitFor(() => expect(saveConfig).toHaveBeenCalledTimes(1));
    const submitted = vi.mocked(saveConfig).mock.calls[0]![0];
    expect(submitted.max_file_size).toBe(oddByteCount); // exact byte count preserved
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
    await waitForSaveButton();
    // Dirty any field so Save is enabled
    fireEvent.change(screen.getByLabelText("Max client load"), {
      target: { value: "300" },
    });
    clickSaveSettings();
    await waitFor(() => expect(saveConfig).toHaveBeenCalledTimes(1));
    const submitted = vi.mocked(saveConfig).mock
      .calls[0]![0] as unknown as Record<string, unknown>;
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
    expect(
      screen.getByLabelText(/minimum uppercase letters/i),
    ).toBeInTheDocument();
    expect(
      screen.getByLabelText(/minimum lowercase letters/i),
    ).toBeInTheDocument();
    expect(screen.getByLabelText(/minimum digits/i)).toBeInTheDocument();
    expect(
      screen.getByLabelText(/minimum special characters/i),
    ).toBeInTheDocument();
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
    clickSaveSettings();
    await waitFor(() => expect(saveConfig).toHaveBeenCalled());
    const sentConfig = vi.mocked(saveConfig).mock.calls[0]![0];
    expect(sentConfig.password_min_length).toBe(12);
    expect(sentConfig.password_min_uppercase).toBe(1);
  });

  it("renders the three tabs (General / Security / MCP)", async () => {
    vi.mocked(getConfig).mockResolvedValue(baseConfig);
    renderPage();

    await waitFor(() =>
      expect(screen.getByRole("tab", { name: /general/i })).toBeInTheDocument(),
    );
    expect(screen.getByRole("tab", { name: /security/i })).toBeInTheDocument();
    expect(screen.getByRole("tab", { name: /mcp/i })).toBeInTheDocument();

    // General is the default tab — its fields are reachable by label.
    expect(screen.getByLabelText("Max client load")).toBeInTheDocument();
    // Security and MCP tab panels are also mounted (keepMounted) so RTL
    // can find their fields by label even without clicking the tab. Mantine 9
    // mounts inactive keepMounted panels on a deferred tick (not the first
    // render), so await the cross-panel field rather than asserting synchronously.
    await waitFor(() =>
      expect(screen.getByLabelText(/minimum length/i)).toBeInTheDocument(),
    );
    expect(screen.getByLabelText(/enable mcp server/i)).toBeInTheDocument();
  });

  it("clears dirty state after a successful save (Save button goes back to disabled)", async () => {
    vi.mocked(getConfig).mockResolvedValue(baseConfig);
    vi.mocked(saveConfig).mockResolvedValue(undefined);
    renderPage();

    await waitForSaveButton();

    // Save starts disabled (nothing dirty yet)
    const saveButton = () =>
      screen.getByRole("button", { name: /save settings/i });
    expect(saveButton()).toBeDisabled();

    // Dirty a field → Save activates
    fireEvent.change(screen.getByLabelText("Max client load"), {
      target: { value: "500" },
    });
    expect(saveButton()).not.toBeDisabled();

    // Click Save → mutation resolves → baseline should advance to current
    // values, so isDirty() returns false again and Save goes back to disabled.
    clickSaveSettings();
    await waitFor(() => expect(saveConfig).toHaveBeenCalledTimes(1));
    await waitFor(() => expect(saveButton()).toBeDisabled());
  });

  it("persists edits from multiple tabs in a single submit (shared form)", async () => {
    vi.mocked(getConfig).mockResolvedValue(baseConfig);
    vi.mocked(saveConfig).mockResolvedValue(undefined);
    renderPage();

    await waitFor(() =>
      expect(screen.getByLabelText("Max client load")).toBeInTheDocument(),
    );

    // Edit a General field
    fireEvent.change(screen.getByLabelText("Max client load"), {
      target: { value: "500" },
    });
    // Edit a Security field (no tab switch needed — keepMounted exposes it)
    fireEvent.change(screen.getByLabelText(/minimum length/i), {
      target: { value: "12" },
    });

    // Save — should persist BOTH edits in one POST /api/config call
    clickSaveSettings();
    await waitFor(() => expect(saveConfig).toHaveBeenCalledTimes(1));
    const submitted = vi.mocked(saveConfig).mock.calls[0]![0];
    expect(submitted.max_client_load).toBe(500);
    expect(submitted.password_min_length).toBe(12);
  });

  // -------------------------------------------------------------------------
  // Regression tests for the form-state hygiene fixes (PR #37 code review).
  // -------------------------------------------------------------------------

  it("does not fire a second saveConfig call when Save is double-clicked while a save is in-flight", async () => {
    // Hold saveConfig open until we explicitly resolve, simulating slow network.
    let resolveSave!: () => void;
    vi.mocked(getConfig).mockResolvedValue(baseConfig);
    vi.mocked(saveConfig).mockReturnValue(
      new Promise<void>((res) => {
        resolveSave = res;
      }),
    );
    renderPage();

    await waitForSaveButton();
    // Dirty a field so Save is enabled
    fireEvent.change(screen.getByLabelText("Max client load"), {
      target: { value: "300" },
    });
    // First click — should trigger one mutation
    clickSaveSettings();
    await waitFor(() => expect(saveConfig).toHaveBeenCalledTimes(1));

    // Mutation is in-flight: Save must be disabled (loading + disabled).
    // A double-click here in the old behavior would fire a second POST.
    const saveBtn = screen.getAllByRole("button", {
      name: /save settings/i,
    })[0]!;
    expect(saveBtn).toBeDisabled();
    fireEvent.click(saveBtn);
    fireEvent.click(saveBtn);
    // Still exactly one call.
    expect(saveConfig).toHaveBeenCalledTimes(1);

    // Let the save complete so the test doesn't hang on unresolved promise.
    resolveSave();
    await waitFor(() => expect(saveBtn).toBeDisabled());
  });

  it("does NOT overwrite user edits when the config query refetches in the background", async () => {
    // Simulate a refetch returning a NEW config object reference with the same
    // values — the populate effect should bail out because the form is dirty.
    vi.mocked(getConfig).mockResolvedValue(baseConfig);
    const { rerender } = renderPage();

    await waitFor(() =>
      expect(screen.getByLabelText("Max client load")).toBeInTheDocument(),
    );

    // User starts editing
    fireEvent.change(screen.getByLabelText("Max client load"), {
      target: { value: "750" },
    });
    expect(screen.getByLabelText("Max client load")).toHaveValue("750");

    // Simulate a background refetch by re-resolving getConfig with a fresh
    // object — same payload, new reference. The component re-renders;
    // useEffect([config]) would fire and call setValues(populated) without
    // the dirty guard, clobbering the user's "750" back to "10000".
    vi.mocked(getConfig).mockResolvedValueOnce({ ...baseConfig });
    rerender(
      <QueryClientProvider
        client={
          new QueryClient({
            defaultOptions: {
              queries: { retry: false },
              mutations: { retry: false },
            },
          })
        }
      >
        <MantineProvider>
          <Notifications />
          <MemoryRouter>
            <SettingsPage />
          </MemoryRouter>
        </MantineProvider>
      </QueryClientProvider>,
    );
    // After "refetch", the user's typed value must still be 750 — NOT 200.
    // (This is the dirty-guard contract: while form.isDirty(), do not repopulate.)
    expect(screen.getByLabelText("Max client load")).toHaveValue("750");
  });

  it("shows an inline error on Max client load when value exceeds the 200000 cap", async () => {
    vi.mocked(getConfig).mockResolvedValue(baseConfig);
    vi.mocked(saveConfig).mockResolvedValue(undefined);
    renderPage();
    await waitForSaveButton();

    // Push value over the 200000 cap
    fireEvent.change(screen.getByLabelText("Max client load"), {
      target: { value: "500000" },
    });

    // Inline error renders under the input
    await waitFor(() =>
      expect(screen.getByText(/maximum is 200000/i)).toBeInTheDocument(),
    );

    // Save is blocked while the form has validation errors — even though
    // the field is dirty, the backend would reject this value with a 400.
    const saveBtn = screen.getAllByRole("button", {
      name: /save settings/i,
    })[0]!;
    expect(saveBtn).toBeDisabled();
    // Confirm no POST fires
    fireEvent.click(saveBtn);
    expect(saveConfig).not.toHaveBeenCalled();
  });

  it("captures live form values in the dirty-reset, not the closure snapshot at submit time", async () => {
    // Slow saveConfig so we can edit between submit and onSuccess.
    let resolveSave!: () => void;
    vi.mocked(getConfig).mockResolvedValue(baseConfig);
    vi.mocked(saveConfig).mockReturnValue(
      new Promise<void>((res) => {
        resolveSave = res;
      }),
    );
    renderPage();
    await waitForSaveButton();

    // Initial edit + click Save
    fireEvent.change(screen.getByLabelText("Max client load"), {
      target: { value: "300" },
    });
    clickSaveSettings();
    await waitFor(() => expect(saveConfig).toHaveBeenCalledTimes(1));

    // While Save is in-flight, user types ANOTHER edit. With the buggy
    // closure-captured `values`, this newer edit would be promoted to the
    // baseline on save success and silently lost (button goes disabled,
    // current value stays in the input but isDirty() returns false). The
    // fix uses form.getValues() so the live value stays dirty.
    fireEvent.change(screen.getByLabelText("Max client load"), {
      target: { value: "400" },
    });

    // Resolve the save — onSuccess runs and resets the baseline to the
    // CURRENT live values (300 was submitted, but live is 400 — baseline
    // becomes 400, so isDirty() is correctly false against the live value
    // 400, NOT against the stale closure 300).
    resolveSave();
    const saveBtn = () =>
      screen.getAllByRole("button", { name: /save settings/i })[0]!;
    await waitFor(() => expect(saveBtn()).toBeDisabled());

    // The value the user typed last must still be visible — not snapped
    // back to anything else.
    expect(screen.getByLabelText("Max client load")).toHaveValue("400");
  });
});

describe("SettingsPage Download config button", () => {
  beforeEach(() => {
    // Mantine's notifications store is a global singleton — prior tests in
    // this file leak "Settings saved" toasts into the DOM, which then make
    // it impossible to assert "no other notifications exist" or to find a
    // specific message by text without ambiguity. clean() resets the store
    // so each test starts from an empty notification list.
    notifications.clean();
    vi.mocked(exportConfig).mockReset();
    vi.mocked(getConfig).mockResolvedValue(baseConfig);
    vi.mocked(saveConfig).mockResolvedValue(undefined);
  });

  it("renders the Download config (JSON) button", async () => {
    renderPage();
    const btn = await screen.findByRole("button", { name: /download config/i });
    expect(btn).toBeInTheDocument();
  });

  it("calls exportConfig and triggers a download when clicked", async () => {
    const createObjectURL = vi.fn(() => "blob:test");
    const revokeObjectURL = vi.fn();
    global.URL.createObjectURL = createObjectURL;
    global.URL.revokeObjectURL = revokeObjectURL;

    const blob = new Blob(['{"roles":[]}'], { type: "application/json" });
    vi.mocked(exportConfig).mockResolvedValue(blob);

    renderPage();
    const btn = await screen.findByRole("button", { name: /download config/i });
    fireEvent.click(btn);

    await waitFor(() => {
      expect(exportConfig).toHaveBeenCalled();
      expect(createObjectURL).toHaveBeenCalledWith(blob);
      expect(revokeObjectURL).toHaveBeenCalledWith("blob:test");
    });
  });

  it("shows an error notification when exportConfig fails", async () => {
    vi.mocked(exportConfig).mockRejectedValue(new Error("Forbidden"));

    renderPage();
    const btn = await screen.findByRole("button", { name: /download config/i });
    fireEvent.click(btn);

    await waitFor(() => {
      expect(
        screen.getByText(/failed to download config/i),
      ).toBeInTheDocument();
    });
  });
});
