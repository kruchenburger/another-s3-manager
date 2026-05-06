import { describe, it, expect, vi } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { MantineProvider } from "@mantine/core";
import { Notifications } from "@mantine/notifications";
import { RoleDrawer } from "@/components/Admin/RoleDrawer";
import type { AppConfig, AppRole } from "@/types/api";

const VALID_AWS_KEY = "AKIAIOSFODNN7EXAMPLE";
const VALID_ARN = "arn:aws:iam::123456789012:role/MyRole";

const baseConfig: AppConfig = {
  roles: [],
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

const r2Role: AppRole = {
  name: "R2",
  type: "s3_compatible",
  endpoint_url: "https://x.r2.cloudflarestorage.com",
  access_key_id: VALID_AWS_KEY,
  secret_access_key: "ORIG",
  region: "auto",
  allowed_buckets: ["bucket-a"],
};

interface RenderOpts {
  opened: boolean;
  mode: "create" | "edit";
  initialRole?: AppRole;
  config?: AppConfig;
  readOnly?: boolean;
  onSubmit?: ReturnType<typeof vi.fn>;
  onClose?: ReturnType<typeof vi.fn>;
  loading?: boolean;
}

function renderDrawer(opts: RenderOpts) {
  const onSubmit = opts.onSubmit ?? vi.fn();
  const onClose = opts.onClose ?? vi.fn();
  const utils = render(
    <MantineProvider>
      <Notifications />
      <RoleDrawer
        opened={opts.opened}
        mode={opts.mode}
        initialRole={opts.initialRole}
        config={opts.config ?? baseConfig}
        readOnly={opts.readOnly ?? false}
        onClose={onClose}
        onSubmit={onSubmit}
        loading={opts.loading}
      />
    </MantineProvider>,
  );
  return { ...utils, onSubmit, onClose };
}

describe("RoleDrawer", () => {
  it("renders nothing when opened=false", () => {
    renderDrawer({ opened: false, mode: "create" });
    expect(screen.queryByRole("textbox", { name: /^name/i })).not.toBeInTheDocument();
  });

  it('mode="create": renders the friendly RoleTypePicker on Step 1, no credential fields visible', async () => {
    renderDrawer({ opened: true, mode: "create" });

    await waitFor(() =>
      expect(
        screen.getByRole("radio", { name: /AWS credential chain/i }),
      ).toBeInTheDocument(),
    );
    expect(screen.queryByLabelText(/^access key id/i)).not.toBeInTheDocument();
  });

  it('mode="create": ASIA prefix rejected', async () => {
    renderDrawer({ opened: true, mode: "create" });

    await waitFor(() =>
      expect(
        screen.getByRole("radio", { name: /Static access key/i }),
      ).toBeInTheDocument(),
    );

    fireEvent.click(screen.getByRole("radio", { name: /Static access key/i }));
    fireEvent.change(screen.getByRole("textbox", { name: /^name/i }), {
      target: { value: "AsiaKey" },
    });
    fireEvent.click(screen.getByRole("button", { name: /next/i }));

    await waitFor(() =>
      expect(screen.getByLabelText(/^access key id/i)).toBeInTheDocument(),
    );
    fireEvent.change(screen.getByLabelText(/^access key id/i), {
      target: { value: "ASIAIOSFODNN7EXAMPLE" },
    });
    fireEvent.change(screen.getByLabelText(/^secret access key/i), {
      target: { value: "anything" },
    });
    fireEvent.click(screen.getByRole("button", { name: /next/i }));

    expect(
      screen.getByText(/AKIA followed by 16 uppercase chars/),
    ).toBeInTheDocument();
    expect(screen.getByText(/STS assume role/i)).toBeInTheDocument();
  });

  it('mode="create": valid default end-to-end calls onSubmit with correct payload', async () => {
    const onSubmit = vi.fn();
    renderDrawer({ opened: true, mode: "create", onSubmit });

    await waitFor(() =>
      expect(screen.getByRole("button", { name: /next/i })).toBeInTheDocument(),
    );

    fireEvent.change(screen.getByRole("textbox", { name: /^name/i }), {
      target: { value: "NewRole" },
    });
    fireEvent.click(screen.getByRole("button", { name: /next/i }));

    await waitFor(() =>
      expect(screen.getByText(/allowed buckets/i)).toBeInTheDocument(),
    );
    fireEvent.click(screen.getByRole("button", { name: /next/i }));

    await waitFor(() =>
      expect(screen.getByRole("button", { name: /save role/i })).toBeInTheDocument(),
    );
    fireEvent.click(screen.getByRole("button", { name: /save role/i }));

    await waitFor(() => expect(onSubmit).toHaveBeenCalledTimes(1));
    const [role, opts] = onSubmit.mock.calls[0]!;
    expect(role.name).toBe("NewRole");
    expect(role.type).toBe("default");
    expect(opts).toEqual({ mode: "create" });
  });

  it('mode="create": duplicate name shows notification and bounces to step 0', async () => {
    const config: AppConfig = {
      ...baseConfig,
      roles: [{ name: "Existing", type: "default" }],
    };
    const onSubmit = vi.fn();
    renderDrawer({ opened: true, mode: "create", config, onSubmit });

    await waitFor(() =>
      expect(screen.getByRole("button", { name: /next/i })).toBeInTheDocument(),
    );

    fireEvent.change(screen.getByRole("textbox", { name: /^name/i }), {
      target: { value: "Existing" },
    });
    fireEvent.click(screen.getByRole("button", { name: /next/i }));
    await waitFor(() =>
      expect(screen.getByText(/allowed buckets/i)).toBeInTheDocument(),
    );
    fireEvent.click(screen.getByRole("button", { name: /next/i }));
    await waitFor(() =>
      expect(screen.getByRole("button", { name: /save role/i })).toBeInTheDocument(),
    );
    fireEvent.click(screen.getByRole("button", { name: /save role/i }));

    await waitFor(() =>
      expect(screen.getByText(/already exists/i)).toBeInTheDocument(),
    );
    expect(onSubmit).not.toHaveBeenCalled();
    // Bounced back to Step 0 — Name input visible and Next button (not Save) shown
    expect(screen.getByRole("textbox", { name: /^name/i })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /next/i })).toBeInTheDocument();
  });

  it('mode="edit": form populated from initialRole', async () => {
    renderDrawer({ opened: true, mode: "edit", initialRole: r2Role });

    await waitFor(() =>
      expect(screen.getByRole("textbox", { name: /^name/i })).toHaveValue("R2"),
    );
    expect(screen.getByRole("textbox", { name: /^name/i })).toBeDisabled();

    const radios = screen.getAllByRole("radio");
    const r2Radio = radios.find(
      (r) => (r as HTMLInputElement).value === "s3_compatible",
    );
    expect(r2Radio).toBeDefined();
    expect((r2Radio as HTMLInputElement).checked).toBe(true);

    expect(screen.getByLabelText(/^endpoint url/i)).toHaveValue(
      "https://x.r2.cloudflarestorage.com",
    );
  });

  it('mode="edit": picker disabled', async () => {
    renderDrawer({ opened: true, mode: "edit", initialRole: r2Role });

    await waitFor(() =>
      expect(screen.getByRole("textbox", { name: /^name/i })).toHaveValue("R2"),
    );

    const radios = screen.getAllByRole("radio");
    expect(radios.length).toBe(5);
    radios.forEach((r) => expect(r).toBeDisabled());
  });

  it('mode="edit": Save click emits role with empty secret when user did not type one', async () => {
    const onSubmit = vi.fn();
    renderDrawer({ opened: true, mode: "edit", initialRole: r2Role, onSubmit });

    await waitFor(() =>
      expect(screen.getByRole("textbox", { name: /^name/i })).toHaveValue("R2"),
    );

    fireEvent.click(screen.getByRole("button", { name: /save changes/i }));

    await waitFor(() => expect(onSubmit).toHaveBeenCalledTimes(1));
    const [role, opts] = onSubmit.mock.calls[0]!;
    expect(role.secret_access_key).toBe("");
    expect(opts).toEqual({ mode: "edit", previousName: "R2" });
  });

  it('mode="edit": readOnly=true disables Save and inputs', async () => {
    renderDrawer({
      opened: true,
      mode: "edit",
      initialRole: r2Role,
      readOnly: true,
    });

    await waitFor(() =>
      expect(screen.getByRole("textbox", { name: /^name/i })).toHaveValue("R2"),
    );

    expect(screen.getByRole("button", { name: /save changes/i })).toBeDisabled();
    expect(screen.getByLabelText(/^endpoint url/i)).toBeDisabled();
    // Picker is also disabled — all 5 type radios non-interactive
    const radios = screen.getAllByRole("radio");
    expect(radios.length).toBe(5);
    radios.forEach((r) => expect(r).toBeDisabled());
  });

  it('mode="edit": legacy ASIA access_key_id does not block Save', async () => {
    const legacyRole: AppRole = {
      ...r2Role,
      type: "credentials",
      endpoint_url: undefined,
      access_key_id: "ASIAIOSFODNN7EXAMPLEXX",
    };
    const onSubmit = vi.fn();
    renderDrawer({
      opened: true,
      mode: "edit",
      initialRole: legacyRole,
      onSubmit,
    });

    await waitFor(() =>
      expect(screen.getByRole("textbox", { name: /^name/i })).toHaveValue("R2"),
    );

    fireEvent.click(screen.getByRole("button", { name: /save changes/i }));

    await waitFor(() => expect(onSubmit).toHaveBeenCalledTimes(1));
  });

  // --- Ported from the deleted RoleNewPage.test.tsx ---

  it('mode="create": blocks Next without a name (validation gate)', async () => {
    renderDrawer({ opened: true, mode: "create" });

    await waitFor(() =>
      expect(screen.getByRole("button", { name: /next/i })).toBeInTheDocument(),
    );
    fireEvent.click(screen.getByRole("button", { name: /next/i }));

    expect(screen.getByRole("textbox", { name: /^name/i })).toBeInTheDocument();
    await waitFor(() => expect(screen.getByText("Required")).toBeInTheDocument());
  });

  it('mode="create": blocks forward Stepper clicks when validation has not passed', async () => {
    renderDrawer({ opened: true, mode: "create" });

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

  it('mode="create": masks secret_access_key in the Review JSON preview', async () => {
    renderDrawer({ opened: true, mode: "create" });

    await waitFor(() =>
      expect(screen.getByRole("button", { name: /next/i })).toBeInTheDocument(),
    );

    fireEvent.click(screen.getByRole("radio", { name: /Static access key/i }));
    fireEvent.change(screen.getByRole("textbox", { name: /^name/i }), {
      target: { value: "TestCred" },
    });
    fireEvent.click(screen.getByRole("button", { name: /next/i }));

    await waitFor(() =>
      expect(screen.getByLabelText(/^access key id/i)).toBeInTheDocument(),
    );
    fireEvent.change(screen.getByLabelText(/^access key id/i), {
      target: { value: VALID_AWS_KEY },
    });
    fireEvent.change(screen.getByLabelText(/^secret access key/i), {
      target: { value: "SUPER_SECRET" },
    });
    fireEvent.click(screen.getByRole("button", { name: /next/i }));

    await waitFor(() =>
      expect(screen.getByRole("button", { name: /save role/i })).toBeInTheDocument(),
    );
    const preview = screen.getByLabelText(/role json/i) as HTMLTextAreaElement;
    expect(preview.value).toContain("***REDACTED***");
    expect(preview.value).not.toContain("SUPER_SECRET");
  });

  it('mode="create": strips stale credentials from the Review preview after type switch', async () => {
    renderDrawer({ opened: true, mode: "create" });

    await waitFor(() =>
      expect(screen.getByRole("button", { name: /next/i })).toBeInTheDocument(),
    );

    fireEvent.click(screen.getByRole("radio", { name: /Static access key/i }));
    fireEvent.change(screen.getByRole("textbox", { name: /^name/i }), {
      target: { value: "Stale1" },
    });
    fireEvent.click(screen.getByRole("button", { name: /next/i }));

    await waitFor(() =>
      expect(screen.getByLabelText(/^access key id/i)).toBeInTheDocument(),
    );
    fireEvent.change(screen.getByLabelText(/^access key id/i), {
      target: { value: VALID_AWS_KEY },
    });
    fireEvent.change(screen.getByLabelText(/^secret access key/i), {
      target: { value: "STALE_SECRET" },
    });

    fireEvent.click(screen.getByRole("button", { name: /previous/i }));
    await waitFor(() =>
      expect(
        screen.getByRole("radio", { name: /AWS credential chain/i }),
      ).toBeInTheDocument(),
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

  it('mode="create": default type Step 2 shows scope-only (Allowed buckets visible, no credential fields)', async () => {
    renderDrawer({ opened: true, mode: "create" });

    await waitFor(() =>
      expect(screen.getByRole("button", { name: /next/i })).toBeInTheDocument(),
    );
    // Default is preselected — fill name, advance
    fireEvent.change(screen.getByRole("textbox", { name: /^name/i }), {
      target: { value: "DefaultRole" },
    });
    fireEvent.click(screen.getByRole("button", { name: /next/i }));
    await waitFor(() =>
      expect(screen.getByText(/allowed buckets/i)).toBeInTheDocument(),
    );
    // No credential fields and no Description on Step 2 for the default type
    expect(screen.queryByLabelText(/^access key id/i)).not.toBeInTheDocument();
    expect(screen.queryByLabelText(/^endpoint url/i)).not.toBeInTheDocument();
    expect(screen.queryByLabelText(/^description$/i)).not.toBeInTheDocument();
  });

  it('mode="create": rejects a malformed Role ARN (assume_role) on Step 2', async () => {
    renderDrawer({ opened: true, mode: "create" });

    await waitFor(() =>
      expect(screen.getByRole("button", { name: /next/i })).toBeInTheDocument(),
    );
    fireEvent.click(screen.getByRole("radio", { name: /STS assume role/i }));
    fireEvent.change(screen.getByRole("textbox", { name: /^name/i }), {
      target: { value: "ArnTest" },
    });
    fireEvent.click(screen.getByRole("button", { name: /next/i }));
    await waitFor(() =>
      expect(screen.getByLabelText(/^role arn/i)).toBeInTheDocument(),
    );
    fireEvent.change(screen.getByLabelText(/^role arn/i), {
      target: { value: "not-an-arn" },
    });
    fireEvent.click(screen.getByRole("button", { name: /next/i }));
    expect(
      screen.queryByRole("button", { name: /save role/i }),
    ).not.toBeInTheDocument();
    expect(
      screen.getByText(/arn:aws:iam::<account-id>:role\/<RoleName>/),
    ).toBeInTheDocument();
  });

  it('mode="create": accepts a well-formed Role ARN', async () => {
    renderDrawer({ opened: true, mode: "create" });

    await waitFor(() =>
      expect(screen.getByRole("button", { name: /next/i })).toBeInTheDocument(),
    );
    fireEvent.click(screen.getByRole("radio", { name: /STS assume role/i }));
    fireEvent.change(screen.getByRole("textbox", { name: /^name/i }), {
      target: { value: "ArnOk" },
    });
    fireEvent.click(screen.getByRole("button", { name: /next/i }));
    await waitFor(() =>
      expect(screen.getByLabelText(/^role arn/i)).toBeInTheDocument(),
    );
    fireEvent.change(screen.getByLabelText(/^role arn/i), {
      target: { value: VALID_ARN },
    });
    fireEvent.click(screen.getByRole("button", { name: /next/i }));
    await waitFor(() =>
      expect(screen.getByRole("button", { name: /save role/i })).toBeInTheDocument(),
    );
  });

  it('mode="create": s3_compatible bypasses the AWS access-key format check (R2/MinIO)', async () => {
    renderDrawer({ opened: true, mode: "create" });

    await waitFor(() =>
      expect(screen.getByRole("button", { name: /next/i })).toBeInTheDocument(),
    );
    fireEvent.click(screen.getByRole("radio", { name: /Other S3-compatible/i }));
    fireEvent.change(screen.getByRole("textbox", { name: /^name/i }), {
      target: { value: "R2Role" },
    });
    fireEvent.click(screen.getByRole("button", { name: /next/i }));
    await waitFor(() =>
      expect(screen.getByLabelText(/^access key id/i)).toBeInTheDocument(),
    );
    // R2-style key (32-char lowercase hex) — would fail AWS regex but must pass here
    fireEvent.change(screen.getByLabelText(/^access key id/i), {
      target: { value: "abcdef0123456789abcdef0123456789" },
    });
    fireEvent.change(screen.getByLabelText(/^secret access key/i), {
      target: { value: "r2secret" },
    });
    fireEvent.change(screen.getByLabelText(/^endpoint url/i), {
      target: { value: "https://x.r2.cloudflarestorage.com" },
    });
    fireEvent.click(screen.getByRole("button", { name: /next/i }));
    await waitFor(() =>
      expect(screen.getByRole("button", { name: /save role/i })).toBeInTheDocument(),
    );
  });

  it("does not leak description from one edited role into the next when switching Edit A → Edit B", async () => {
    // Regression: opening Edit on a role with a description, then opening
    // Edit on a different role without description, used to keep the first
    // role's description visible in the form. Cause: initialRole spread on
    // top of form.setValues only writes keys present on the new role —
    // missing keys (description = undefined) leave the prior value in place.
    const roleA: AppRole = {
      name: "RoleA",
      type: "default",
      description: "First role description",
      allowed_buckets: [],
    };
    const roleB: AppRole = {
      name: "RoleB",
      type: "default",
      // intentionally NO description property
      allowed_buckets: [],
    };

    const onSubmit = vi.fn();
    const onClose = vi.fn();
    const { rerender } = render(
      <MantineProvider>
        <Notifications />
        <RoleDrawer
          opened={true}
          mode="edit"
          initialRole={roleA}
          config={baseConfig}
          readOnly={false}
          onClose={onClose}
          onSubmit={onSubmit}
        />
      </MantineProvider>,
    );

    // Edit A: description shows
    await waitFor(() =>
      expect(
        (screen.getByLabelText(/^description$/i) as HTMLInputElement).value,
      ).toBe("First role description"),
    );

    // Switch to Edit B (drawer stays open, only initialRole changes)
    rerender(
      <MantineProvider>
        <Notifications />
        <RoleDrawer
          opened={true}
          mode="edit"
          initialRole={roleB}
          config={baseConfig}
          readOnly={false}
          onClose={onClose}
          onSubmit={onSubmit}
        />
      </MantineProvider>,
    );

    await waitFor(() =>
      expect(
        (screen.getByRole("textbox", { name: /^name/i }) as HTMLInputElement)
          .value,
      ).toBe("RoleB"),
    );
    // Description must be EMPTY for roleB, not "First role description"
    expect(
      (screen.getByLabelText(/^description$/i) as HTMLInputElement).value,
    ).toBe("");
  });

  it("does not leak edit-mode values into a subsequent create-mode session", async () => {
    // Regression: clicking Edit on a row, closing the drawer, then clicking
    // "Add role" used to show the previously-edited role's data prefilled in
    // the create form. The bug was that form.reset() restores the values
    // baseline that the edit-open had moved via setInitialValues(); the
    // follow-up bug was that setValues({...EMPTY_ROLE}) only overwrote keys
    // that EMPTY_ROLE explicitly listed, so fields like `description` kept
    // their previous string value.
    const r2RoleWithDescription: AppRole = {
      ...r2Role,
      description: "Cloudflare R2 prod",
    };
    const onSubmit = vi.fn();
    const onClose = vi.fn();
    const { rerender } = render(
      <MantineProvider>
        <Notifications />
        <RoleDrawer
          opened={true}
          mode="edit"
          initialRole={r2RoleWithDescription}
          config={baseConfig}
          readOnly={false}
          onClose={onClose}
          onSubmit={onSubmit}
        />
      </MantineProvider>,
    );

    // Edit-mode populated the form with R2's values
    await waitFor(() =>
      expect(
        (screen.getByRole("textbox", { name: /^name/i }) as HTMLInputElement)
          .value,
      ).toBe("R2"),
    );
    expect(
      (screen.getByLabelText(/^description$/i) as HTMLInputElement).value,
    ).toBe("Cloudflare R2 prod");

    // Close the drawer (parent flips opened=false)
    rerender(
      <MantineProvider>
        <Notifications />
        <RoleDrawer
          opened={false}
          mode="edit"
          initialRole={r2RoleWithDescription}
          config={baseConfig}
          readOnly={false}
          onClose={onClose}
          onSubmit={onSubmit}
        />
      </MantineProvider>,
    );

    // Reopen in create mode (parent navigates to /admin/roles/new)
    rerender(
      <MantineProvider>
        <Notifications />
        <RoleDrawer
          opened={true}
          mode="create"
          initialRole={undefined}
          config={baseConfig}
          readOnly={false}
          onClose={onClose}
          onSubmit={onSubmit}
        />
      </MantineProvider>,
    );

    // Step 1 fields must all be empty
    await waitFor(() =>
      expect(
        (screen.getByRole("textbox", { name: /^name/i }) as HTMLInputElement)
          .value,
      ).toBe(""),
    );
    expect(
      (screen.getByLabelText(/^description$/i) as HTMLInputElement).value,
    ).toBe("");
    // Step 1 has no endpoint URL field — credentials live on Step 2.
    expect(screen.queryByLabelText(/^endpoint url/i)).not.toBeInTheDocument();
    // The default radio is the active one (form.values.type === "default")
    const defaultRadio = screen
      .getAllByRole("radio")
      .find((r) => (r as HTMLInputElement).value === "default");
    expect(defaultRadio).toBeDefined();
    expect((defaultRadio as HTMLInputElement).checked).toBe(true);
  });
});
