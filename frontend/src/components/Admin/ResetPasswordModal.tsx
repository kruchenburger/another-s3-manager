import { Alert, Button, Modal, PasswordInput, Stack } from "@mantine/core";
import { useForm } from "@mantine/form";
import { usePasswordPolicy } from "@/features/auth/hooks/usePasswordPolicy";
import {
  PasswordRequirementsList,
  meetsPolicy,
} from "@/components/Auth/PasswordRequirementsList";

interface ResetPasswordModalProps {
  opened: boolean;
  username?: string;
  onClose: () => void;
  onSubmit: (newPassword: string) => void;
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
    initialValues: { password: "" },
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
          onSubmit(v.password);
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
          </Stack>
          <Button
            type="submit"
            loading={loading}
            color="amber"
            disabled={!policy && !policyFailed}
          >
            Reset password
          </Button>
        </Stack>
      </form>
    </Modal>
  );
}
