import {
  Anchor,
  Code,
  Group,
  Radio,
  Stack,
  Text,
  Tooltip,
} from "@mantine/core";
import {
  Cloud,
  Globe,
  Info,
  Key,
  Repeat,
  User,
} from "lucide-react";
import type { ReactNode } from "react";
import type { AppRole } from "@/types/api";

type RoleType = AppRole["type"];

interface Option {
  value: RoleType;
  label: string;
  icon: ReactNode;
  /** One-liner shown beneath the label. */
  description: ReactNode;
  /** Optional richer explanation revealed via Tooltip on the info icon. */
  details?: ReactNode;
}

export const OPTIONS: Option[] = [
  {
    value: "default",
    label: "AWS credential chain",
    icon: <Cloud size={18} />,
    description: <>Resolve credentials via the standard AWS chain. No keys stored in this app.</>,
    details: (
      <>
        Sources tried in order: env vars (AWS_ACCESS_KEY_ID etc.), ~/.aws/config
        profile, EC2/ECS/EKS instance metadata, or credential_process hooks like{" "}
        <Anchor
          href="https://docs.aws.amazon.com/rolesanywhere/latest/userguide/introduction.html"
          target="_blank"
          rel="noopener noreferrer"
          inherit
          underline="always"
        >
          IAM Roles Anywhere
        </Anchor>
        .{" "}
        <Anchor
          href="https://docs.aws.amazon.com/sdkref/latest/guide/standardized-credentials.html"
          target="_blank"
          rel="noopener noreferrer"
          inherit
          underline="always"
        >
          Full chain reference
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
        Reference a profile from <code>~/.aws/credentials</code> or AWS SSO config.
      </>
    ),
  },
  {
    value: "assume_role",
    label: "STS assume role",
    icon: <Repeat size={18} />,
    description: <>Assume a target IAM role via STS. Base creds need sts:AssumeRole.</>,
  },
  {
    value: "credentials",
    label: "Static access key + secret",
    icon: <Key size={18} />,
    description: <>Store an AWS access key + secret directly. Simplest, least secure.</>,
  },
  {
    value: "s3_compatible",
    label: "Other S3-compatible service",
    icon: <Globe size={18} />,
    description: <>Cloudflare R2, MinIO, Backblaze B2, Wasabi, etc. Requires endpoint URL.</>,
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
                  {opt.details && (
                    <Tooltip
                      label={opt.details}
                      multiline
                      w={340}
                      withArrow
                      position="right"
                      color="dark"
                      c="white"
                      events={{ hover: true, focus: true, touch: true }}
                    >
                      <Info
                        size={14}
                        aria-label={`More details about ${opt.label}`}
                        style={{ cursor: "help", opacity: 0.6 }}
                      />
                    </Tooltip>
                  )}
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
