import { Button, NumberInput, Stack, Text } from "@mantine/core";
import type { UseFormReturnType } from "@mantine/form";
import type { SettingsFormValues } from "./SettingsPage";

interface SettingsSecurityTabProps {
  form: UseFormReturnType<SettingsFormValues>;
  readOnly: boolean;
  isPending: boolean;
}

export function SettingsSecurityTab({ form, readOnly, isPending }: SettingsSecurityTabProps) {
  return (
    <Stack gap="md" maw={520} mt="md">
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
      {!readOnly && (
        <Button type="submit" loading={isPending} disabled={!form.isDirty()}>
          Save settings
        </Button>
      )}
    </Stack>
  );
}
