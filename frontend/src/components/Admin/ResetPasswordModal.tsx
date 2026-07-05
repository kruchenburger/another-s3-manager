import {
  Alert,
  Button,
  Checkbox,
  Modal,
  PasswordInput,
  Stack,
} from "@mantine/core";
import { useForm } from "@mantine/form";
import { AlertTriangle } from "lucide-react";
import { usePasswordPolicy } from "@/features/auth/hooks/usePasswordPolicy";
import {
  PasswordRequirementsList,
  meetsPolicy,
} from "@/components/Auth/PasswordRequirementsList";

interface ResetPasswordModalProps {
  opened: boolean;
  username?: string;
  onClose: () => void;
  onSubmit: (newPassword: string, mustChangePassword: boolean) => void;
  loading?: boolean;
}

export function ResetPasswordModal({
  opened,
  username,
  onClose,
  onSubmit,
  loading,
}: ResetPasswordModalProps) {
  const { data: policy, isError: policyFailed } = usePasswordPolicy();
  const form = useForm({
    initialValues: { password: "", must_change_password: true },
    validate: {
      password: (v) => {
        if (!policy) return v && v.length > 0 ? null : "Required";
        return meetsPolicy(v, policy) ? null : "Password does not meet policy";
      },
    },
  });

  return (
    <Modal
      opened={opened}
      onClose={onClose}
      title={`Reset password for ${username ?? ""}`}
      centered
    >
      <form
        onSubmit={form.onSubmit((v) => {
          onSubmit(v.password, v.must_change_password);
          form.reset();
        })}
      >
        <Stack gap="md">
          <Alert color="yellow">
            This will overwrite the user&apos;s password — they will need the
            new value to log in.
          </Alert>
          <Stack gap={4}>
            <PasswordInput
              label="New password"
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
                Couldn't load password policy — the server will validate the new
                password on save.
              </Alert>
            )}
            <Checkbox
              mt={4}
              label="Require password change on next login"
              description="If unchecked, the user can keep this password."
              {...form.getInputProps("must_change_password", {
                type: "checkbox",
              })}
            />
          </Stack>
          <Button
            type="submit"
            loading={loading}
            disabled={!policy && !policyFailed}
          >
            Reset password
          </Button>
        </Stack>
      </form>
    </Modal>
  );
}
