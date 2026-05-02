import { Button, Container, PasswordInput, Stack, Title } from "@mantine/core";
import { useForm } from "@mantine/form";
import { useNavigate } from "react-router-dom";
import { useChangeMyPassword } from "@/features/auth/hooks/useChangeMyPassword";
import { runWithToasts } from "@/utils/mutationToast";

export function ChangePasswordPage() {
  const navigate = useNavigate();
  const mutation = useChangeMyPassword();

  const form = useForm({
    initialValues: { current: "", next: "", confirm: "" },
    validate: {
      current: (value) => (value.length === 0 ? "Required" : null),
      next: (value) => (value.length < 8 ? "8+ characters" : null),
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
        <Title order={2}>Change my password</Title>
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
            <PasswordInput
              label="Confirm new password"
              required
              {...form.getInputProps("confirm")}
            />
            <Button
              type="submit"
              color="amber"
              loading={mutation.isPending}
            >
              Change password
            </Button>
          </Stack>
        </form>
      </Stack>
    </Container>
  );
}
