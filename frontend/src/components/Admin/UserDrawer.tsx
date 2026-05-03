import {
  Button,
  Drawer,
  PasswordInput,
  Stack,
  Switch,
  TagsInput,
  TextInput,
  Tooltip,
} from "@mantine/core";
import { useForm } from "@mantine/form";
import { useEffect } from "react";
import type { AdminUser } from "@/types/api";
import { usePasswordPolicy } from "@/features/auth/hooks/usePasswordPolicy";
import {
  PasswordRequirementsList,
  meetsPolicy,
} from "@/components/Auth/PasswordRequirementsList";

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
    >
      <form
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
        <Stack gap="md">
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
            // Dropdown opens downward by default; portal keeps it from being
            // clipped by the drawer. Save button sits just below — the user
            // scrolls the drawer to reach it when the dropdown is open with
            // many roles.
            comboboxProps={{ withinPortal: true }}
            maxDropdownHeight={220}
            // Cap the pill area so 15+ selected roles don't blow up the
            // input vertically. Pills wrap onto multiple rows but the
            // container scrolls instead of pushing other fields away.
            styles={{
              inputField: { minWidth: 60 },
              pillsList: { maxHeight: 96, overflowY: "auto" },
              pill: { fontSize: 12 },
            }}
            {...form.getInputProps("allowed_roles")}
          />
          <Button
            type="submit"
            loading={loading}
            disabled={mode === "create" && !policy && !policyFailed}
          >
            {mode === "create" ? "Create user" : "Save changes"}
          </Button>
        </Stack>
      </form>
    </Drawer>
  );
}
