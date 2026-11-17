import { NumberInput, Stack, Text } from "@mantine/core";
import type { UseFormReturnType } from "@mantine/form";
import type { AppConfig } from "@/types/api";
import type { SettingsFormValues } from "./SettingsPage";

interface SettingsSecurityTabProps {
  form: UseFormReturnType<SettingsFormValues>;
  readOnly: boolean;
  runtime?: AppConfig["auth_runtime"];
}

export function SettingsSecurityTab({
  form,
  readOnly,
  runtime,
}: SettingsSecurityTabProps) {
  return (
    <Stack gap="md" maw={520} mt="md">
      {runtime && (
        <Stack gap="xs">
          <Text fw={600}>Single sign-on · read only</Text>
          <Text size="sm">Issuer: {runtime.issuer || "Not configured"}</Text>
          <Text size="sm">
            Client ID: {runtime.client_id || "Not configured"}
          </Text>
          <Text size="sm">
            Mapping: {runtime.mapping_mode} · Local login:{" "}
            {runtime.effective_local_login}
          </Text>
        </Stack>
      )}
      <Text size="sm" c="dimmed">
        Enforced when a user changes their own password or an admin
        creates/resets another user&apos;s password. Set any value to 0 to
        disable that requirement. Existing passwords are not re-validated.
      </Text>
      <NumberInput
        label="Minimum length"
        description="Set to 0 to disable"
        min={0}
        max={50}
        step={1}
        disabled={readOnly}
        {...form.getInputProps("password_min_length")}
      />
      <NumberInput
        label="Minimum uppercase letters"
        description="Set to 0 to disable"
        min={0}
        max={50}
        step={1}
        disabled={readOnly}
        {...form.getInputProps("password_min_uppercase")}
      />
      <NumberInput
        label="Minimum lowercase letters"
        description="Set to 0 to disable"
        min={0}
        max={50}
        step={1}
        disabled={readOnly}
        {...form.getInputProps("password_min_lowercase")}
      />
      <NumberInput
        label="Minimum digits"
        description="Set to 0 to disable"
        min={0}
        max={50}
        step={1}
        disabled={readOnly}
        {...form.getInputProps("password_min_digits")}
      />
      <NumberInput
        label="Minimum special characters"
        description="Set to 0 to disable"
        min={0}
        max={50}
        step={1}
        disabled={readOnly}
        {...form.getInputProps("password_min_special")}
      />
    </Stack>
  );
}
