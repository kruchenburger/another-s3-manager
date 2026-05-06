import { describe, it, expect, vi } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { MantineProvider } from "@mantine/core";
import { Notifications } from "@mantine/notifications";
import { RoleDrawer } from "@/components/Admin/RoleDrawer";
import type { AppConfig, AppRole } from "@/types/api";

const VALID_AWS_KEY = "AKIAIOSFODNN7EXAMPLE";

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
});
