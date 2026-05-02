import { Alert, Button, Modal, PasswordInput, Stack } from "@mantine/core";
import { useForm } from "@mantine/form";

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
  const form = useForm({
    initialValues: { password: "" },
    validate: { password: (v) => (v.length < 8 ? "8+ chars" : null) },
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
          <PasswordInput
            label="New password"
            required
            {...form.getInputProps("password")}
          />
          <Button type="submit" loading={loading} color="amber">
            Reset password
          </Button>
        </Stack>
      </form>
    </Modal>
  );
}
