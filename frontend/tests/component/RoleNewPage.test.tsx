import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { MantineProvider } from "@mantine/core";
import { Notifications } from "@mantine/notifications";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter, Routes, Route } from "react-router-dom";
import { RoleNewPage } from "@/pages/admin/RoleNewPage";

vi.mock("@/features/admin/api/adminApi", () => ({
  getConfig: vi.fn(),
  saveConfig: vi.fn(),
}));
import { getConfig, saveConfig } from "@/features/admin/api/adminApi";

const baseConfig = {
  roles: [{ name: "Existing", type: "default" as const }],
  items_per_page: 200,
  enable_lazy_loading: true,
  max_file_size: 100 * 1024 * 1024,
  disable_deletion: false,
  is_read_only: false,
};

function renderWizard() {
  const qc = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
  return render(
    <QueryClientProvider client={qc}>
      <MantineProvider>
        <Notifications />
        <MemoryRouter initialEntries={["/admin/roles/new"]}>
          <Routes>
            <Route path="/admin/roles/new" element={<RoleNewPage />} />
            <Route path="/admin/roles" element={<div>Roles list</div>} />
          </Routes>
        </MemoryRouter>
      </MantineProvider>
    </QueryClientProvider>,
  );
}

describe("RoleNewPage", () => {
  beforeEach(() => {
    vi.mocked(getConfig).mockReset();
    vi.mocked(saveConfig).mockReset();
  });

  it("renders all 5 type radio options on Step 1 with descriptions", async () => {
    vi.mocked(getConfig).mockResolvedValue(baseConfig);
    renderWizard();

    await waitFor(() => expect(screen.getByText(/new role/i)).toBeInTheDocument());

    // All 5 types visible as radios. Mantine accessible name = full label
    // (the radio's bold name + the description text). Use ^anchor regex so
    // a description that *mentions* another type name (e.g. credentials's
    // description references "Default or Assume Role") doesn't double-match.
    expect(screen.getByRole("radio", { name: /^default/i })).toBeInTheDocument();
    expect(screen.getByRole("radio", { name: /^profile/i })).toBeInTheDocument();
    expect(screen.getByRole("radio", { name: /^assume_role/i })).toBeInTheDocument();
    expect(screen.getByRole("radio", { name: /^credentials/i })).toBeInTheDocument();
    expect(screen.getByRole("radio", { name: /^s3_compatible/i })).toBeInTheDocument();
  });

  it("includes the AWS docs link on the Default type description", async () => {
    vi.mocked(getConfig).mockResolvedValue(baseConfig);
    renderWizard();

    await waitFor(() =>
      expect(screen.getByRole("link", { name: /learn more/i })).toBeInTheDocument(),
    );
    const link = screen.getByRole("link", { name: /learn more/i });
    expect(link).toHaveAttribute(
      "href",
      "https://docs.aws.amazon.com/sdkref/latest/guide/standardized-credentials.html",
    );
  });

  it("blocks Next without a name (validation gate)", async () => {
    vi.mocked(getConfig).mockResolvedValue(baseConfig);
    renderWizard();

    await waitFor(() =>
      expect(screen.getByRole("button", { name: /next/i })).toBeInTheDocument(),
    );
    fireEvent.click(screen.getByRole("button", { name: /next/i }));

    // Stays on Step 1 — Name field still visible (Step 2 would hide name+type).
    // Mantine appends " *" to required label text, so match flexibly.
    expect(screen.getByLabelText(/^name/i)).toBeInTheDocument();
    // Validation error appears
    await waitFor(() => expect(screen.getByText("Required")).toBeInTheDocument());
  });

  it("rejects a duplicate name on Save with a notification, jumps back to Step 1", async () => {
    vi.mocked(getConfig).mockResolvedValue(baseConfig);
    renderWizard();

    await waitFor(() =>
      expect(screen.getByRole("button", { name: /next/i })).toBeInTheDocument(),
    );

    // Step 1: type defaults to "default", name = "Existing" (collides)
    fireEvent.change(screen.getByLabelText(/^name/i), { target: { value: "Existing" } });
    fireEvent.click(screen.getByRole("button", { name: /next/i }));

    // For "default" type Step 2 is skipped → we land on Step 3 (Review). Save button visible.
    await waitFor(() =>
      expect(screen.getByRole("button", { name: /save role/i })).toBeInTheDocument(),
    );
    fireEvent.click(screen.getByRole("button", { name: /save role/i }));

    // Notification appears with the collision message
    await waitFor(() =>
      expect(screen.getByText(/already exists/i)).toBeInTheDocument(),
    );
    // saveConfig was NOT called
    expect(saveConfig).not.toHaveBeenCalled();
    // Active step bounced back to Step 1 — Next button visible (Save button gone)
    expect(screen.getByRole("button", { name: /next/i })).toBeInTheDocument();
  });

  it("creates a new default role end-to-end", async () => {
    vi.mocked(getConfig).mockResolvedValue(baseConfig);
    vi.mocked(saveConfig).mockResolvedValue(undefined);
    renderWizard();

    await waitFor(() =>
      expect(screen.getByRole("button", { name: /next/i })).toBeInTheDocument(),
    );

    fireEvent.change(screen.getByLabelText(/^name/i), { target: { value: "NewRole" } });
    fireEvent.click(screen.getByRole("button", { name: /next/i }));
    // For default type, lands on Review (Step 3)
    await waitFor(() =>
      expect(screen.getByRole("button", { name: /save role/i })).toBeInTheDocument(),
    );
    fireEvent.click(screen.getByRole("button", { name: /save role/i }));

    await waitFor(() => expect(saveConfig).toHaveBeenCalledTimes(1));
    const submitted = vi.mocked(saveConfig).mock.calls[0]![0];
    expect(submitted.roles).toHaveLength(2);  // existing + new
    const newRole = submitted.roles.find((r) => r.name === "NewRole");
    expect(newRole).toBeDefined();
    expect(newRole!.type).toBe("default");

    // Navigated to /admin/roles list
    await waitFor(() => expect(screen.getByText(/roles list/i)).toBeInTheDocument());
  });

  it("blocks forward Stepper clicks when validation hasn't passed", async () => {
    vi.mocked(getConfig).mockResolvedValue(baseConfig);
    renderWizard();

    await waitFor(() =>
      expect(screen.getByRole("button", { name: /next/i })).toBeInTheDocument(),
    );

    // Try to jump directly to Review (Step 3) by clicking the step header.
    // Mantine 8 Stepper headers may be `tab` role or plain text — try both.
    const reviewByRole = screen.queryByRole("tab", { name: /review/i });
    const reviewStepHeader = reviewByRole ?? screen.getByText(/^review$/i);
    fireEvent.click(reviewStepHeader);

    // Should NOT have advanced — Step 1 (Name field) is still visible
    expect(screen.getByLabelText(/^name/i)).toBeInTheDocument();
    // Save button should NOT have appeared (would only show on Step 3)
    expect(screen.queryByRole("button", { name: /save role/i })).not.toBeInTheDocument();
  });

  it("blocks Next from Step 2 (Credentials) when required field is missing", async () => {
    vi.mocked(getConfig).mockResolvedValue(baseConfig);
    renderWizard();
    await waitFor(() =>
      expect(screen.getByRole("button", { name: /next/i })).toBeInTheDocument(),
    );
    // Pick credentials type, fill name, advance to Step 2
    fireEvent.click(screen.getByRole("radio", { name: /^credentials/i }));
    fireEvent.change(screen.getByLabelText(/^name/i), { target: { value: "TestCred" } });
    fireEvent.click(screen.getByRole("button", { name: /next/i }));
    // Step 2 fields visible but empty
    await waitFor(() =>
      expect(screen.getByLabelText(/^access key id/i)).toBeInTheDocument(),
    );
    fireEvent.click(screen.getByRole("button", { name: /next/i }));
    // Should NOT advance to Review — Save button must not appear
    expect(screen.queryByRole("button", { name: /save role/i })).not.toBeInTheDocument();
    // Validation errors visible
    expect(screen.getAllByText("Required").length).toBeGreaterThan(0);
  });

  it("does not persist credential fields when role type is default (stale fields stripped)", async () => {
    vi.mocked(getConfig).mockResolvedValue(baseConfig);
    vi.mocked(saveConfig).mockResolvedValue(undefined);
    renderWizard();
    await waitFor(() =>
      expect(screen.getByRole("button", { name: /next/i })).toBeInTheDocument(),
    );
    // Pick credentials, fill name + secrets
    fireEvent.click(screen.getByRole("radio", { name: /^credentials/i }));
    fireEvent.change(screen.getByLabelText(/^name/i), { target: { value: "TestStale" } });
    fireEvent.click(screen.getByRole("button", { name: /next/i }));
    await waitFor(() =>
      expect(screen.getByLabelText(/^access key id/i)).toBeInTheDocument(),
    );
    fireEvent.change(screen.getByLabelText(/^access key id/i), { target: { value: "STALE_KEY" } });
    fireEvent.change(screen.getByLabelText(/^secret access key/i), { target: { value: "STALE_SECRET" } });
    // Go back, switch to default
    fireEvent.click(screen.getByRole("button", { name: /previous/i }));
    await waitFor(() =>
      expect(screen.getByRole("radio", { name: /^default/i })).toBeInTheDocument(),
    );
    fireEvent.click(screen.getByRole("radio", { name: /^default/i }));
    fireEvent.click(screen.getByRole("button", { name: /next/i }));
    await waitFor(() =>
      expect(screen.getByRole("button", { name: /save role/i })).toBeInTheDocument(),
    );
    fireEvent.click(screen.getByRole("button", { name: /save role/i }));
    await waitFor(() => expect(saveConfig).toHaveBeenCalledTimes(1));
    const submitted = vi.mocked(saveConfig).mock.calls[0]![0];
    const newRole = submitted.roles.find((r) => r.name === "TestStale")!;
    expect(newRole.type).toBe("default");
    expect(newRole.access_key_id).toBeUndefined();
    expect(newRole.secret_access_key).toBeUndefined();
  });

  it("masks secret_access_key in the Review JSON preview", async () => {
    vi.mocked(getConfig).mockResolvedValue(baseConfig);
    renderWizard();

    await waitFor(() =>
      expect(screen.getByRole("button", { name: /next/i })).toBeInTheDocument(),
    );

    // Step 1: type=credentials, name=TestCred
    fireEvent.click(screen.getByRole("radio", { name: /^credentials/i }));
    fireEvent.change(screen.getByLabelText(/^name/i), { target: { value: "TestCred" } });
    fireEvent.click(screen.getByRole("button", { name: /next/i }));

    // Step 2: fill credentials including a secret
    await waitFor(() =>
      expect(screen.getByLabelText(/^access key id/i)).toBeInTheDocument(),
    );
    fireEvent.change(screen.getByLabelText(/^access key id/i), { target: { value: "AKIA..." } });
    fireEvent.change(screen.getByLabelText(/^secret access key/i), { target: { value: "SUPER_SECRET" } });
    fireEvent.click(screen.getByRole("button", { name: /next/i }));

    // Step 3: Review — JSON preview should mask the secret
    await waitFor(() =>
      expect(screen.getByRole("button", { name: /save role/i })).toBeInTheDocument(),
    );
    const preview = screen.getByLabelText(/role json/i) as HTMLTextAreaElement;
    expect(preview.value).toContain("***REDACTED***");
    expect(preview.value).not.toContain("SUPER_SECRET");
  });
});
