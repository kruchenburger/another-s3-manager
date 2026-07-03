import {
  Cloud,
  Globe,
  HelpCircle,
  Key,
  Repeat,
  User,
  type LucideIcon,
} from "lucide-react";
import type { AppRole } from "@/types/api";

export type RoleType = AppRole["type"];

export interface RoleTypeMeta {
  value: RoleType;
  /** Compact label for table badges ("Access keys"). */
  badgeLabel: string;
  /** Full label shown in the wizard picker ("Static access key + secret"). */
  label: string;
  icon: LucideIcon;
  /** Plain-string one-liner: badge tooltip. Rich JSX stays in the picker. */
  description: string;
}

// Single source of truth for role-type naming — consumed by the RolesPage
// badge AND RoleTypePicker's OPTIONS. ORDER MATTERS: the picker renders
// radios in this order and a picker test indexes into the DOM order. Keep
// default / profile / assume_role / credentials / s3_compatible.
export const ROLE_TYPE_META: RoleTypeMeta[] = [
  {
    value: "default",
    badgeLabel: "AWS chain",
    label: "AWS credential chain",
    icon: Cloud,
    description:
      "Resolves credentials via the standard AWS chain — no keys stored in this app.",
  },
  {
    value: "profile",
    badgeLabel: "AWS profile",
    label: "Named AWS profile",
    icon: User,
    description:
      "References a named profile from ~/.aws/credentials or ~/.aws/config.",
  },
  {
    value: "assume_role",
    badgeLabel: "Assume role",
    label: "STS assume role",
    icon: Repeat,
    description: "Assumes a target IAM role via STS using the base credentials.",
  },
  {
    value: "credentials",
    badgeLabel: "Access keys",
    label: "Static access key + secret",
    icon: Key,
    description: "An AWS access key + secret stored directly in this app.",
  },
  {
    value: "s3_compatible",
    badgeLabel: "S3-compatible",
    label: "Other S3-compatible service",
    icon: Globe,
    description:
      "Cloudflare R2, MinIO, Backblaze B2, Wasabi, etc. — custom endpoint URL.",
  },
];

/** Meta for a type; unknown types degrade to the raw value + HelpCircle. */
export function roleTypeMeta(type: RoleType): RoleTypeMeta {
  return (
    ROLE_TYPE_META.find((m) => m.value === type) ?? {
      value: type,
      badgeLabel: type,
      label: type,
      icon: HelpCircle,
      description: "Unknown role type.",
    }
  );
}
