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
  // Unicode-aware character classes via \p{...} regex with /u flag, matching
  // the backend's Python str.isupper/.islower/.isdigit semantics. Avoids the
  // "Стронг123 fails uppercase rule on the client but passes on the server"
  // mismatch.
  if (policy.password_min_uppercase > 0) {
    const count = (password.match(/\p{Lu}/gu) || []).length;
    reqs.push({
      label: `At least ${policy.password_min_uppercase} uppercase letter${policy.password_min_uppercase === 1 ? "" : "s"}`,
      met: count >= policy.password_min_uppercase,
    });
  }
  if (policy.password_min_lowercase > 0) {
    const count = (password.match(/\p{Ll}/gu) || []).length;
    reqs.push({
      label: `At least ${policy.password_min_lowercase} lowercase letter${policy.password_min_lowercase === 1 ? "" : "s"}`,
      met: count >= policy.password_min_lowercase,
    });
  }
  if (policy.password_min_digits > 0) {
    const count = (password.match(/\p{N}/gu) || []).length;
    reqs.push({
      label: `At least ${policy.password_min_digits} digit${policy.password_min_digits === 1 ? "" : "s"}`,
      met: count >= policy.password_min_digits,
    });
  }
  if (policy.password_min_special > 0) {
    // Special = anything not letter, not number. Matches backend `not c.isalnum()`.
    const count = (password.match(/[^\p{L}\p{N}]/gu) || []).length;
    reqs.push({
      label: `At least ${policy.password_min_special} special character${policy.password_min_special === 1 ? "" : "s"}`,
      met: count >= policy.password_min_special,
    });
  }
  return reqs;
}

// Scheme-aware status colors. A fixed shade can't pass WCAG AA contrast in both
// themes against their very different backgrounds (white vs. the dark body), so
// `light-dark()` picks a darker shade on light surfaces and a lighter one on
// dark. (Mantine 9's dark body tipped the previous flat `red.7` to 4.03:1 — just
// under the 4.5:1 minimum — on the empty-field state.) Mirrors the project's
// existing `light-dark()` use in the login shell.
const MET_COLOR =
  "light-dark(var(--mantine-color-green-9), var(--mantine-color-green-5))";
const UNMET_COLOR =
  "light-dark(var(--mantine-color-red-8), var(--mantine-color-red-5))";

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
            <Check size={14} color={MET_COLOR} />
          ) : (
            <X size={14} color={UNMET_COLOR} />
          )}
          <Text size="xs" c={r.met ? MET_COLOR : UNMET_COLOR}>
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
