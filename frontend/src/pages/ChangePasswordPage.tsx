import { Alert, Button, Container, PasswordInput, Stack, Title } from "@mantine/core";
import { AlertTriangle } from "lucide-react";
import { useForm } from "@mantine/form";
import { useNavigate } from "react-router-dom";
import { useChangeMyPassword } from "@/features/auth/hooks/useChangeMyPassword";
import { usePasswordPolicy } from "@/features/auth/hooks/usePasswordPolicy";
import {
  PasswordRequirementsList,
  meetsPolicy,
} from "@/components/Auth/PasswordRequirementsList";
import { runWithToasts } from "@/utils/mutationToast";

export function ChangePasswordPage() {
  const navigate = useNavigate();
  const mutation = useChangeMyPassword();
  const { data: policy, isError: policyFailed } = usePasswordPolicy();

  const form = useForm({
    initialValues: { current: "", next: "", confirm: "" },
    validate: {
      current: (value) => (value.length === 0 ? "Required" : null),
      next: (value) => {
        if (!policy) return null; // server is source of truth; let it through
        return meetsPolicy(value, policy) ? null : "Password does not meet policy";
      },
      confirm: (value, values) =>
        value === values.next ? null : "Does not match new password",
    },
  });

  const handleSubmit = (values: typeof form.values): void => {
    runWithToasts(
      mutation,
      { current_password: values.current, new_password: values.next },
      "Password changed successfully",
      () => navigate("/"),
    );
  };

  return (
    <Container size="xs" py="xl">
      <Stack gap="md">
        <Title order={2}>Change password</Title>
        <form onSubmit={form.onSubmit(handleSubmit)}>
          <Stack gap="md">
            <PasswordInput
              label="Current password"
              required
              {...form.getInputProps("current")}
            />
            <PasswordInput
              label="New password"
              required
              {...form.getInputProps("next")}
            />
            {policy && (
              <PasswordRequirementsList password={form.values.next} policy={policy} />
            )}
            {policyFailed && (
              <Alert
                color="yellow"
                variant="light"
                icon={<AlertTriangle size={16} />}
              >
                Couldn't load password policy — the server will validate your new password on save.
              </Alert>
            )}
            <PasswordInput
              label="Confirm new password"
              required
              {...form.getInputProps("confirm")}
            />
            <Button
              type="submit"
              color="amber"
              loading={mutation.isPending}
              disabled={!policy && !policyFailed}
            >
              Change password
            </Button>
          </Stack>
        </form>
      </Stack>
    </Container>
  );
}
