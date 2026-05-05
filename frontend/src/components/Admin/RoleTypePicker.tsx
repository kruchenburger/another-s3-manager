import { Anchor, Code, Group, Radio, Stack, Text } from "@mantine/core";
import { Cloud, Globe, Key, Repeat, User } from "lucide-react";
import type { ReactNode } from "react";
import type { AppRole } from "@/types/api";

type RoleType = AppRole["type"];

interface Option {
  value: RoleType;
  label: string;
  icon: ReactNode;
  description: ReactNode;
}

const OPTIONS: Option[] = [
  {
    value: "default",
    label: "AWS instance role (recommended for cloud)",
    icon: <Cloud size={18} />,
    description: (
      <>
        Use credentials from the EC2/ECS/EKS environment automatically. No keys
        needed in the manager. Pick this when running on AWS.{" "}
        <Anchor
          href="https://docs.aws.amazon.com/sdkref/latest/guide/standardized-credentials.html"
          target="_blank"
          rel="noopener noreferrer"
        >
          Learn more about AWS credential precedence
        </Anchor>
      </>
    ),
  },
  {
    value: "profile",
    label: "Named AWS profile",
    icon: <User size={18} />,
    description: (
      <>
        Reference a profile from <code>~/.aws/credentials</code> or AWS SSO
        config. The container needs that file mounted.
      </>
    ),
  },
  {
    value: "assume_role",
    label: "STS assume role",
    icon: <Repeat size={18} />,
    description: (
      <>
        Assume a target IAM role via STS. Container needs base credentials with
        sts:AssumeRole permission for the target.
      </>
    ),
  },
  {
    value: "credentials",
    label: "Static access key + secret",
    icon: <Key size={18} />,
    description: (
      <>
        Provide AWS access key ID and secret directly. Simplest setup, but the
        keys live in this app's config — prefer "instance role" or "assume
        role" when possible.
      </>
    ),
  },
  {
    value: "s3_compatible",
    label: "Other S3-compatible service",
    icon: <Globe size={18} />,
    description: (
      <>
        For Cloudflare R2, MinIO, Backblaze B2, Wasabi, DigitalOcean Spaces,
        etc. Requires the service endpoint URL.
      </>
    ),
  },
];

interface Props {
  value: RoleType;
  onChange: (next: RoleType) => void;
  disabled?: boolean;
}

export function RoleTypePicker({ value, onChange, disabled }: Props) {
  return (
    <Radio.Group value={value} onChange={(v) => onChange(v as RoleType)}>
      <Stack gap="sm" mt="xs">
        {OPTIONS.map((opt) => (
          <Radio
            key={opt.value}
            value={opt.value}
            disabled={disabled}
            label={
              <Stack gap={2}>
                <Group gap="xs" wrap="nowrap">
                  {opt.icon}
                  <Text fw={500}>{opt.label}</Text>
                  <Code>{opt.value}</Code>
                </Group>
                <Text size="xs" c="dimmed">
                  {opt.description}
                </Text>
              </Stack>
            }
          />
        ))}
      </Stack>
    </Radio.Group>
  );
}
