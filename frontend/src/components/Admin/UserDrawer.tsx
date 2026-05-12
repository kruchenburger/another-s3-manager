import {
  Alert,
  Button,
  Divider,
  Drawer,
  PasswordInput,
  Stack,
  Switch,
  TagsInput,
  TextInput,
  Tooltip,
} from "@mantine/core";
import { AlertTriangle } from "lucide-react";
import { useForm } from "@mantine/form";
import { useEffect } from "react";
import type { AdminUser } from "@/types/api";
import { usePasswordPolicy } from "@/features/auth/hooks/usePasswordPolicy";
import {
  PasswordRequirementsList,
  meetsPolicy,
} from "@/components/Auth/PasswordRequirementsList";
import { UserTokensList } from "@/components/Admin/UserTokensList";

export type UserDrawerMode = "create" | "edit";

export interface UserDrawerCreatePayload {
  mode: "create";
  username: string;
  password: string; // required
  is_admin: boolean;
  allowed_roles: string[];
}

export interface UserDrawerEditPayload {
  mode: "edit";
  username: string;
  is_admin: boolean;
  allowed_roles: string[];
}

export type UserDrawerSubmitPayload =
  | UserDrawerCreatePayload
  | UserDrawerEditPayload;

interface UserDrawerProps {
  opened: boolean;
  mode: UserDrawerMode;
  initialUser?: AdminUser; // required for edit
  currentUsername: string; // who is editing — for self-protect
  availableRoles: string[]; // for the TagsInput autocomplete
  onClose: () => void;
  onSubmit: (payload: UserDrawerSubmitPayload) => void;
  loading?: boolean;
}

export function UserDrawer({
  opened,
  mode,
  initialUser,
  currentUsername,
  availableRoles,
  onClose,
  onSubmit,
  loading,
}: UserDrawerProps) {
  const isSelf =
    mode === "edit" &&
    initialUser !== undefined &&
    initialUser.username === currentUsername;

  const { data: policy, isError: policyFailed } = usePasswordPolicy();

  const form = useForm({
    initialValues: {
      username: "",
      password: "",
      is_admin: false,
      allowed_roles: [] as string[],
    },
    validate: {
      username: (v) =>
        mode === "create" && (!v || v.length < 3 || /\s/.test(v))
          ? "3+ chars, no spaces"
          : null,
      password: (v) => {
        if (mode !== "create") return null;
        if (!policy) return v && v.length > 0 ? null : "Required";
        return meetsPolicy(v, policy) ? null : "Password does not meet policy";
      },
    },
  });

  useEffect(() => {
    if (mode === "edit" && initialUser) {
      form.setValues({
        username: initialUser.username,
        password: "",
        is_admin: initialUser.is_admin,
        allowed_roles: initialUser.allowed_roles,
      });
    } else if (mode === "create") {
      form.reset();
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [mode, initialUser, opened]);

  return (
    <Drawer
      opened={opened}
      onClose={onClose}
      position="right"
      size="md"
      title={
        mode === "create"
          ? "Create user"
          : `Edit user ${initialUser?.username ?? ""}`
      }
      // Make the drawer body a flex column so the form can stretch and the
      // Save button can stick to the bottom regardless of dropdown height.
      // `calc(100% - 60px)` accounts for the Mantine Drawer header height
      // (Drawer body's `height: 100%` would otherwise overflow the viewport
      // because the header sits in the same column).
      styles={{
        body: {
          display: "flex",
          flexDirection: "column",
          height: "calc(100% - 60px)",
          overflow: "hidden",
        },
      }}
    >
      <form
        style={{ display: "flex", flexDirection: "column", flex: 1, minHeight: 0 }}
        onSubmit={form.onSubmit((values) => {
          if (mode === "create") {
            onSubmit({
              mode: "create",
              username: values.username,
              password: values.password,
              is_admin: values.is_admin,
              allowed_roles: values.allowed_roles,
            });
          } else {
            onSubmit({
              mode: "edit",
              username: values.username,
              is_admin: values.is_admin,
              allowed_roles: values.allowed_roles,
            });
          }
        })}
      >
        <Stack gap="md" style={{ flex: 1, overflowY: "auto", paddingRight: 4 }}>
          <TextInput
            label="Username"
            required
            disabled={mode === "edit"}
            {...form.getInputProps("username")}
          />
          {mode === "create" && (
            <Stack gap={4}>
              <PasswordInput
                label="Password"
                required
                {...form.getInputProps("password")}
              />
              {policy && (
                <PasswordRequirementsList
                  password={form.values.password}
                  policy={policy}
                />
              )}
              {policyFailed && (
                <Alert
                  color="yellow"
                  variant="light"
                  icon={<AlertTriangle size={16} />}
                >
                  Couldn't load password policy — the server will validate the new password on save.
                </Alert>
              )}
            </Stack>
          )}
          <Tooltip
            label="You can't remove your own admin rights."
            disabled={!isSelf}
            position="left"
          >
            <Switch
              label="Administrator"
              disabled={isSelf}
              {...form.getInputProps("is_admin", { type: "checkbox" })}
            />
          </Tooltip>
          <TagsInput
            label="Allowed roles"
            description="Roles this user can access. Empty = no roles."
            data={availableRoles}
            // Dropdown opens downward via portal so it isn't clipped by the
            // drawer; pill area is height-capped so 15+ selected roles
            // don't balloon the input. The Save button below this control
            // is pinned to the drawer bottom (see sticky footer markup) so
            // a long dropdown never hides it.
            comboboxProps={{ withinPortal: true }}
            maxDropdownHeight={220}
            styles={{
              inputField: { minWidth: 60 },
              pillsList: { maxHeight: 96, overflowY: "auto" },
              pill: { fontSize: 12 },
            }}
            {...form.getInputProps("allowed_roles")}
          />
          {mode === "edit" && initialUser && (
            <>
              <Divider my="xs" />
              <UserTokensList
                username={initialUser.username}
                userId={initialUser.id}
              />
            </>
          )}
        </Stack>
        <div
          style={{
            paddingTop: 12,
            marginTop: 12,
            borderTop: "1px solid var(--mantine-color-default-border)",
          }}
        >
          <Button
            type="submit"
            loading={loading}
            disabled={mode === "create" && !policy && !policyFailed}
            fullWidth
          >
            {mode === "create" ? "Create user" : "Save changes"}
          </Button>
        </div>
      </form>
    </Drawer>
  );
}
