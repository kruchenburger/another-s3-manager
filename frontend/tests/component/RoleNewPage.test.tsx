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

const VALID_AWS_KEY = "AKIAIOSFODNN7EXAMPLE";
const VALID_ARN = "arn:aws:iam::123456789012:role/MyRole";

const baseConfig = {
  roles: [{ name: "Existing", type: "default" as const }],
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

    expect(screen.getByRole("radio", { name: /AWS credential chain/i })).toBeInTheDocument();
    expect(screen.getByRole("radio", { name: /Named AWS profile/i })).toBeInTheDocument();
    expect(screen.getByRole("radio", { name: /STS assume role/i })).toBeInTheDocument();
    expect(screen.getByRole("radio", { name: /Static access key/i })).toBeInTheDocument();
    expect(screen.getByRole("radio", { name: /Other S3-compatible/i })).toBeInTheDocument();
  });

  it("includes the AWS docs link on the Default type description", async () => {
    vi.mocked(getConfig).mockResolvedValue(baseConfig);
    renderWizard();
    await waitFor(() =>
      expect(
        screen.getByLabelText(/more details about AWS credential chain/i),
      ).toBeInTheDocument(),
    );
  });

  it("blocks Next without a name (validation gate)", async () => {
    vi.mocked(getConfig).mockResolvedValue(baseConfig);
    renderWizard();

    await waitFor(() =>
      expect(screen.getByRole("button", { name: /next/i })).toBeInTheDocument(),
    );
    fireEvent.click(screen.getByRole("button", { name: /next/i }));

    expect(screen.getByRole("textbox", { name: /^name/i })).toBeInTheDocument();
    await waitFor(() => expect(screen.getByText("Required")).toBeInTheDocument());
  });

  it("rejects a duplicate name on Save with a notification, jumps back to Step 1", async () => {
    vi.mocked(getConfig).mockResolvedValue(baseConfig);
    renderWizard();

    await waitFor(() =>
      expect(screen.getByRole("button", { name: /next/i })).toBeInTheDocument(),
    );

    // Step 1: type defaults to "default", name = "Existing" (collides)
    fireEvent.change(screen.getByRole("textbox", { name: /^name/i }), { target: { value: "Existing" } });
    fireEvent.click(screen.getByRole("button", { name: /next/i }));

    // Step 2 (Scope & details) is reached even for default — only allowed_buckets + description show
    await waitFor(() =>
      expect(screen.getByText(/allowed buckets/i)).toBeInTheDocument(),
    );
    fireEvent.click(screen.getByRole("button", { name: /next/i }));

    // Step 3 (Review)
    await waitFor(() =>
      expect(screen.getByRole("button", { name: /save role/i })).toBeInTheDocument(),
    );
    fireEvent.click(screen.getByRole("button", { name: /save role/i }));

    await waitFor(() =>
      expect(screen.getByText(/already exists/i)).toBeInTheDocument(),
    );
    expect(saveConfig).not.toHaveBeenCalled();
    // Active step bounced back to Step 1 — Next button visible (Save button gone)
    expect(screen.getByRole("button", { name: /next/i })).toBeInTheDocument();
  });

  it("creates a new default role end-to-end (now visits Step 2 to set scope)", async () => {
    vi.mocked(getConfig).mockResolvedValue(baseConfig);
    vi.mocked(saveConfig).mockResolvedValue(undefined);
    renderWizard();

    await waitFor(() =>
      expect(screen.getByRole("button", { name: /next/i })).toBeInTheDocument(),
    );

    fireEvent.change(screen.getByRole("textbox", { name: /^name/i }), { target: { value: "NewRole" } });
    fireEvent.click(screen.getByRole("button", { name: /next/i }));
    // Step 2 — only Allowed buckets + Description (no credential fields for default)
    await waitFor(() =>
      expect(screen.getByText(/allowed buckets/i)).toBeInTheDocument(),
    );
    expect(screen.queryByLabelText(/^access key id/i)).not.toBeInTheDocument();
    expect(screen.queryByLabelText(/^secret access key/i)).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: /next/i }));
    // Step 3
    await waitFor(() =>
      expect(screen.getByRole("button", { name: /save role/i })).toBeInTheDocument(),
    );
    fireEvent.click(screen.getByRole("button", { name: /save role/i }));

    await waitFor(() => expect(saveConfig).toHaveBeenCalledTimes(1));
    const submitted = vi.mocked(saveConfig).mock.calls[0]![0];
    expect(submitted.roles).toHaveLength(2);
    const newRole = submitted.roles.find((r) => r.name === "NewRole");
    expect(newRole).toBeDefined();
    expect(newRole!.type).toBe("default");
    await waitFor(() => expect(screen.getByText(/roles list/i)).toBeInTheDocument());
  });

  it("blocks forward Stepper clicks when validation hasn't passed", async () => {
    vi.mocked(getConfig).mockResolvedValue(baseConfig);
    renderWizard();

    await waitFor(() =>
      expect(screen.getByRole("button", { name: /next/i })).toBeInTheDocument(),
    );

    const reviewStepHeader =
      screen.queryByRole("tab", { name: /review/i }) ??
      screen.getByRole("button", { name: /review & save/i });
    fireEvent.click(reviewStepHeader);

    expect(screen.getByRole("textbox", { name: /^name/i })).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /save role/i })).not.toBeInTheDocument();
  });

  it("blocks Next from Step 2 (credentials) when required field is missing", async () => {
    vi.mocked(getConfig).mockResolvedValue(baseConfig);
    renderWizard();
    await waitFor(() =>
      expect(screen.getByRole("button", { name: /next/i })).toBeInTheDocument(),
    );
    fireEvent.click(screen.getByRole("radio", { name: /Static access key/i }));
    fireEvent.change(screen.getByRole("textbox", { name: /^name/i }), { target: { value: "TestCred" } });
    fireEvent.click(screen.getByRole("button", { name: /next/i }));
    await waitFor(() =>
      expect(screen.getByLabelText(/^access key id/i)).toBeInTheDocument(),
    );
    fireEvent.click(screen.getByRole("button", { name: /next/i }));
    expect(screen.queryByRole("button", { name: /save role/i })).not.toBeInTheDocument();
    expect(screen.getAllByText("Required").length).toBeGreaterThan(0);
  });

  it("does not persist credential fields when role type is default (stale fields stripped)", async () => {
    vi.mocked(getConfig).mockResolvedValue(baseConfig);
    vi.mocked(saveConfig).mockResolvedValue(undefined);
    renderWizard();
    await waitFor(() =>
      expect(screen.getByRole("button", { name: /next/i })).toBeInTheDocument(),
    );
    fireEvent.click(screen.getByRole("radio", { name: /Static access key/i }));
    fireEvent.change(screen.getByRole("textbox", { name: /^name/i }), { target: { value: "TestStale" } });
    fireEvent.click(screen.getByRole("button", { name: /next/i }));
    await waitFor(() =>
      expect(screen.getByLabelText(/^access key id/i)).toBeInTheDocument(),
    );
    fireEvent.change(screen.getByLabelText(/^access key id/i), { target: { value: VALID_AWS_KEY } });
    fireEvent.change(screen.getByLabelText(/^secret access key/i), { target: { value: "STALE_SECRET" } });
    // Back → switch to default → Next (Step 2 still rendered, just no creds) → Next
    fireEvent.click(screen.getByRole("button", { name: /previous/i }));
    await waitFor(() =>
      expect(screen.getByRole("radio", { name: /AWS credential chain/i })).toBeInTheDocument(),
    );
    fireEvent.click(screen.getByRole("radio", { name: /AWS credential chain/i }));
    fireEvent.click(screen.getByRole("button", { name: /next/i }));
    // Step 2 visible — no credential fields for default
    await waitFor(() =>
      expect(screen.getByText(/allowed buckets/i)).toBeInTheDocument(),
    );
    expect(screen.queryByLabelText(/^access key id/i)).not.toBeInTheDocument();
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

    fireEvent.click(screen.getByRole("radio", { name: /Static access key/i }));
    fireEvent.change(screen.getByRole("textbox", { name: /^name/i }), { target: { value: "TestCred" } });
    fireEvent.click(screen.getByRole("button", { name: /next/i }));

    await waitFor(() =>
      expect(screen.getByLabelText(/^access key id/i)).toBeInTheDocument(),
    );
    fireEvent.change(screen.getByLabelText(/^access key id/i), { target: { value: VALID_AWS_KEY } });
    fireEvent.change(screen.getByLabelText(/^secret access key/i), { target: { value: "SUPER_SECRET" } });
    fireEvent.click(screen.getByRole("button", { name: /next/i }));

    await waitFor(() =>
      expect(screen.getByRole("button", { name: /save role/i })).toBeInTheDocument(),
    );
    const preview = screen.getByLabelText(/role json/i) as HTMLTextAreaElement;
    expect(preview.value).toContain("***REDACTED***");
    expect(preview.value).not.toContain("SUPER_SECRET");
  });

  it("strips stale credentials from the Review preview after type switch", async () => {
    vi.mocked(getConfig).mockResolvedValue(baseConfig);
    renderWizard();

    await waitFor(() =>
      expect(screen.getByRole("button", { name: /next/i })).toBeInTheDocument(),
    );

    fireEvent.click(screen.getByRole("radio", { name: /Static access key/i }));
    fireEvent.change(screen.getByRole("textbox", { name: /^name/i }), { target: { value: "Stale1" } });
    fireEvent.click(screen.getByRole("button", { name: /next/i }));

    await waitFor(() =>
      expect(screen.getByLabelText(/^access key id/i)).toBeInTheDocument(),
    );
    fireEvent.change(screen.getByLabelText(/^access key id/i), { target: { value: VALID_AWS_KEY } });
    fireEvent.change(screen.getByLabelText(/^secret access key/i), { target: { value: "STALE_SECRET" } });

    fireEvent.click(screen.getByRole("button", { name: /previous/i }));
    await waitFor(() =>
      expect(screen.getByRole("radio", { name: /AWS credential chain/i })).toBeInTheDocument(),
    );
    fireEvent.click(screen.getByRole("radio", { name: /AWS credential chain/i }));
    fireEvent.click(screen.getByRole("button", { name: /next/i }));
    // Step 2 (no creds for default) → Next → Review
    await waitFor(() =>
      expect(screen.getByText(/allowed buckets/i)).toBeInTheDocument(),
    );
    fireEvent.click(screen.getByRole("button", { name: /next/i }));

    await waitFor(() =>
      expect(screen.getByRole("button", { name: /save role/i })).toBeInTheDocument(),
    );
    const preview = screen.getByLabelText(/role json/i) as HTMLTextAreaElement;
    expect(preview.value).toContain('"type": "default"');
    expect(preview.value).not.toContain(VALID_AWS_KEY);
    expect(preview.value).not.toContain("STALE_SECRET");
    expect(preview.value).not.toContain("access_key_id");
    expect(preview.value).not.toContain("secret_access_key");
  });

  it("renders the new Stepper labels (Choose type / Scope & details / Review & save)", async () => {
    vi.mocked(getConfig).mockResolvedValue(baseConfig);
    renderWizard();
    await waitFor(() =>
      expect(screen.getByRole("button", { name: /next/i })).toBeInTheDocument(),
    );
    expect(screen.getByText(/choose type/i)).toBeInTheDocument();
    expect(screen.getByText(/scope & details/i)).toBeInTheDocument();
    expect(screen.getByText(/review & save/i)).toBeInTheDocument();
  });

  it('Step 1 (step="type") does NOT render credential fields', async () => {
    vi.mocked(getConfig).mockResolvedValue(baseConfig);
    renderWizard();
    await waitFor(() =>
      expect(screen.getByRole("button", { name: /next/i })).toBeInTheDocument(),
    );
    fireEvent.click(screen.getByRole("radio", { name: /Static access key/i }));
    expect(screen.queryByLabelText(/^access key id/i)).not.toBeInTheDocument();
    expect(screen.queryByLabelText(/^secret access key/i)).not.toBeInTheDocument();
  });

  it("default type still shows Allowed buckets + Description on Step 2 (no credential fields)", async () => {
    vi.mocked(getConfig).mockResolvedValue(baseConfig);
    renderWizard();
    await waitFor(() =>
      expect(screen.getByRole("button", { name: /next/i })).toBeInTheDocument(),
    );
    // Default is preselected — fill name, advance
    fireEvent.change(screen.getByRole("textbox", { name: /^name/i }), { target: { value: "DefaultRole" } });
    fireEvent.click(screen.getByRole("button", { name: /next/i }));
    await waitFor(() =>
      expect(screen.getByText(/allowed buckets/i)).toBeInTheDocument(),
    );
    expect(screen.getByLabelText(/^description$/i)).toBeInTheDocument();
    expect(screen.queryByLabelText(/^access key id/i)).not.toBeInTheDocument();
    expect(screen.queryByLabelText(/^endpoint url/i)).not.toBeInTheDocument();
  });

  it("rejects a malformed Role ARN (assume_role) on Step 2", async () => {
    vi.mocked(getConfig).mockResolvedValue(baseConfig);
    renderWizard();
    await waitFor(() =>
      expect(screen.getByRole("button", { name: /next/i })).toBeInTheDocument(),
    );
    fireEvent.click(screen.getByRole("radio", { name: /STS assume role/i }));
    fireEvent.change(screen.getByRole("textbox", { name: /^name/i }), { target: { value: "ArnTest" } });
    fireEvent.click(screen.getByRole("button", { name: /next/i }));
    await waitFor(() =>
      expect(screen.getByLabelText(/^role arn/i)).toBeInTheDocument(),
    );
    fireEvent.change(screen.getByLabelText(/^role arn/i), { target: { value: "not-an-arn" } });
    fireEvent.click(screen.getByRole("button", { name: /next/i }));
    expect(screen.queryByRole("button", { name: /save role/i })).not.toBeInTheDocument();
    expect(
      screen.getByText(/arn:aws:iam::<account-id>:role\/<RoleName>/),
    ).toBeInTheDocument();
  });

  it("accepts a well-formed Role ARN", async () => {
    vi.mocked(getConfig).mockResolvedValue(baseConfig);
    renderWizard();
    await waitFor(() =>
      expect(screen.getByRole("button", { name: /next/i })).toBeInTheDocument(),
    );
    fireEvent.click(screen.getByRole("radio", { name: /STS assume role/i }));
    fireEvent.change(screen.getByRole("textbox", { name: /^name/i }), { target: { value: "ArnOk" } });
    fireEvent.click(screen.getByRole("button", { name: /next/i }));
    await waitFor(() =>
      expect(screen.getByLabelText(/^role arn/i)).toBeInTheDocument(),
    );
    fireEvent.change(screen.getByLabelText(/^role arn/i), { target: { value: VALID_ARN } });
    fireEvent.click(screen.getByRole("button", { name: /next/i }));
    await waitFor(() =>
      expect(screen.getByRole("button", { name: /save role/i })).toBeInTheDocument(),
    );
  });

  it("rejects a non-AWS-format access_key_id for the credentials type", async () => {
    vi.mocked(getConfig).mockResolvedValue(baseConfig);
    renderWizard();
    await waitFor(() =>
      expect(screen.getByRole("button", { name: /next/i })).toBeInTheDocument(),
    );
    fireEvent.click(screen.getByRole("radio", { name: /Static access key/i }));
    fireEvent.change(screen.getByRole("textbox", { name: /^name/i }), { target: { value: "BadKey" } });
    fireEvent.click(screen.getByRole("button", { name: /next/i }));
    await waitFor(() =>
      expect(screen.getByLabelText(/^access key id/i)).toBeInTheDocument(),
    );
    fireEvent.change(screen.getByLabelText(/^access key id/i), { target: { value: "garbage" } });
    fireEvent.change(screen.getByLabelText(/^secret access key/i), { target: { value: "anything" } });
    fireEvent.click(screen.getByRole("button", { name: /next/i }));
    expect(screen.queryByRole("button", { name: /save role/i })).not.toBeInTheDocument();
    expect(
      screen.getByText(/AKIA or ASIA followed by 16 uppercase chars/),
    ).toBeInTheDocument();
  });

  it("does NOT enforce AWS access-key format for s3_compatible (R2/MinIO use other formats)", async () => {
    vi.mocked(getConfig).mockResolvedValue(baseConfig);
    renderWizard();
    await waitFor(() =>
      expect(screen.getByRole("button", { name: /next/i })).toBeInTheDocument(),
    );
    fireEvent.click(screen.getByRole("radio", { name: /Other S3-compatible/i }));
    fireEvent.change(screen.getByRole("textbox", { name: /^name/i }), { target: { value: "R2Role" } });
    fireEvent.click(screen.getByRole("button", { name: /next/i }));
    await waitFor(() =>
      expect(screen.getByLabelText(/^access key id/i)).toBeInTheDocument(),
    );
    // R2-style key (32-char lowercase hex) — would fail AWS regex but must pass here
    fireEvent.change(screen.getByLabelText(/^access key id/i), { target: { value: "abcdef0123456789abcdef0123456789" } });
    fireEvent.change(screen.getByLabelText(/^secret access key/i), { target: { value: "r2secret" } });
    fireEvent.change(screen.getByLabelText(/^endpoint url/i), { target: { value: "https://x.r2.cloudflarestorage.com" } });
    fireEvent.click(screen.getByRole("button", { name: /next/i }));
    await waitFor(() =>
      expect(screen.getByRole("button", { name: /save role/i })).toBeInTheDocument(),
    );
  });
});
