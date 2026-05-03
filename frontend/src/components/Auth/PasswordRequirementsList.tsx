import { Group, Stack, Text } from "@mantine/core";
import { Check, X } from "lucide-react";
import type { PasswordPolicy } from "@/types/api";

interface Requirement {
  label: string;
  met: boolean;
}

function evaluate(password: string, policy: PasswordPolicy): Requirement[] {
  const reqs: Requirement[] = [];
  if (policy.password_min_length > 0) {
    reqs.push({
      label: `At least ${policy.password_min_length} character${policy.password_min_length === 1 ? "" : "s"}`,
      met: password.length >= policy.password_min_length,
    });
  }
  if (policy.password_min_uppercase > 0) {
    // ASCII-only on the client. Backend uses Python's Unicode-aware
    // .isupper() and remains source of truth for non-ASCII users.
    const count = [...password].filter((c) => c >= "A" && c <= "Z").length;
    reqs.push({
      label: `At least ${policy.password_min_uppercase} uppercase letter${policy.password_min_uppercase === 1 ? "" : "s"}`,
      met: count >= policy.password_min_uppercase,
    });
  }
  if (policy.password_min_lowercase > 0) {
    const count = [...password].filter((c) => c >= "a" && c <= "z").length;
    reqs.push({
      label: `At least ${policy.password_min_lowercase} lowercase letter${policy.password_min_lowercase === 1 ? "" : "s"}`,
      met: count >= policy.password_min_lowercase,
    });
  }
  if (policy.password_min_digits > 0) {
    const count = [...password].filter((c) => c >= "0" && c <= "9").length;
    reqs.push({
      label: `At least ${policy.password_min_digits} digit${policy.password_min_digits === 1 ? "" : "s"}`,
      met: count >= policy.password_min_digits,
    });
  }
  if (policy.password_min_special > 0) {
    const count = [...password].filter(
      (c) => !((c >= "A" && c <= "Z") || (c >= "a" && c <= "z") || (c >= "0" && c <= "9")),
    ).length;
    reqs.push({
      label: `At least ${policy.password_min_special} special character${policy.password_min_special === 1 ? "" : "s"}`,
      met: count >= policy.password_min_special,
    });
  }
  return reqs;
}

export function PasswordRequirementsList({
  password,
  policy,
}: {
  password: string;
  policy: PasswordPolicy;
}) {
  const reqs = evaluate(password, policy);
  if (reqs.length === 0) return null; // policy fully disabled
  return (
    <Stack gap={4}>
      {reqs.map((r) => (
        <Group key={r.label} gap="xs" wrap="nowrap">
          {r.met ? (
            <Check size={14} color="var(--mantine-color-green-7)" />
          ) : (
            <X size={14} color="var(--mantine-color-red-7)" />
          )}
          <Text size="xs" c={r.met ? "green.7" : "red.7"}>
            {r.label}
          </Text>
        </Group>
      ))}
    </Stack>
  );
}

/**
 * Helper for forms: returns true when the password meets ALL enabled rules,
 * so callers can disable submit / set form validation.
 */
export function meetsPolicy(password: string, policy: PasswordPolicy): boolean {
  return evaluate(password, policy).every((r) => r.met);
}
