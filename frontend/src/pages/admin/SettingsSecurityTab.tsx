import {
  Badge,
  Box,
  Divider,
  Group,
  NumberInput,
  Paper,
  Stack,
  Text,
} from "@mantine/core";
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
      {runtime && <SingleSignOnSummary runtime={runtime} />}
      {runtime && <Divider />}
      <Text fw={600} size="sm">
        Password policy
      </Text>
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

const MAPPING_LABELS: Record<string, string> = {
  sync: "Sync at every sign-in",
  initial: "Only when the account is created",
};

const LOCAL_LOGIN_LABELS: Record<string, string> = {
  all: "All users",
  admins: "Administrators only",
  off: "Off",
};

function SingleSignOnSummary({
  runtime,
}: {
  runtime: NonNullable<AppConfig["auth_runtime"]>;
}) {
  const rows: Array<[string, string]> = runtime.oidc_enabled
    ? [
        ["Identity provider", runtime.issuer],
        ["Client ID", runtime.client_id],
        [
          "Roles from the provider",
          MAPPING_LABELS[runtime.mapping_mode] ?? runtime.mapping_mode,
        ],
        [
          "Password sign-in",
          LOCAL_LOGIN_LABELS[runtime.effective_local_login] ??
            runtime.effective_local_login,
        ],
      ]
    : [
        [
          "Password sign-in",
          LOCAL_LOGIN_LABELS[runtime.effective_local_login] ??
            runtime.effective_local_login,
        ],
      ];
  return (
    <Paper withBorder radius="md" p="md" aria-label="Single sign-on">
      <Stack gap="sm">
        <Group justify="space-between" wrap="nowrap">
          <Text fw={600} size="sm">
            Single sign-on
          </Text>
          <Group gap="xs" wrap="nowrap">
            {runtime.oidc_enabled ? (
              <Badge
                variant="light"
                color={runtime.oidc_available ? "green" : "orange"}
              >
                {runtime.oidc_available ? "Available" : "Provider unreachable"}
              </Badge>
            ) : (
              <Badge variant="light" color="gray">
                Not configured
              </Badge>
            )}
            <Badge variant="outline" color="gray">
              Read only
            </Badge>
          </Group>
        </Group>
        <Box
          style={{
            display: "grid",
            gridTemplateColumns: "max-content 1fr",
            columnGap: "var(--mantine-spacing-lg)",
            rowGap: 6,
          }}
        >
          {rows.map(([label, value]) => (
            <SummaryRow key={label} label={label} value={value} />
          ))}
        </Box>
        <Text size="xs" c="dimmed">
          Set through environment variables and config.json. Secrets are never
          shown here.
        </Text>
      </Stack>
    </Paper>
  );
}

function SummaryRow({ label, value }: { label: string; value: string }) {
  return (
    <>
      <Text size="sm" c="dimmed">
        {label}
      </Text>
      <Text size="sm" style={{ overflowWrap: "anywhere" }}>
        {value || "Not configured"}
      </Text>
    </>
  );
}
