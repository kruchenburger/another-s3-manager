import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import { MantineProvider } from "@mantine/core";
import {
  PasswordRequirementsList,
  meetsPolicy,
} from "@/components/Auth/PasswordRequirementsList";
import type { PasswordPolicy } from "@/types/api";

const DEFAULT_POLICY: PasswordPolicy = {
  password_min_length: 8,
  password_min_uppercase: 1,
  password_min_lowercase: 1,
  password_min_digits: 1,
  password_min_special: 0,
};

function renderList(password: string, policy: PasswordPolicy = DEFAULT_POLICY) {
  return render(
    <MantineProvider>
      <PasswordRequirementsList password={password} policy={policy} />
    </MantineProvider>,
  );
}

describe("PasswordRequirementsList", () => {
  it("renders one row per enabled rule", () => {
    renderList("");
    expect(screen.getByText(/at least 8 characters/i)).toBeInTheDocument();
    expect(screen.getByText(/at least 1 uppercase letter/i)).toBeInTheDocument();
    expect(screen.getByText(/at least 1 lowercase letter/i)).toBeInTheDocument();
    expect(screen.getByText(/at least 1 digit/i)).toBeInTheDocument();
    expect(screen.queryByText(/special/i)).not.toBeInTheDocument();
  });

  it("returns null when every rule is disabled (policy all zeros)", () => {
    const zeroPolicy: PasswordPolicy = {
      password_min_length: 0,
      password_min_uppercase: 0,
      password_min_lowercase: 0,
      password_min_digits: 0,
      password_min_special: 0,
    };
    renderList("anything", zeroPolicy);
    // Component renders nothing — no requirement rows of any kind.
    // (MantineProvider still injects a <style> tag, so we can't check container.firstChild.)
    expect(screen.queryByText(/at least/i)).not.toBeInTheDocument();
  });

  it("includes the special rule when policy_min_special > 0", () => {
    renderList("Strong1!", { ...DEFAULT_POLICY, password_min_special: 1 });
    expect(screen.getByText(/at least 1 special character/i)).toBeInTheDocument();
  });

  it("uses plural label when minimum is 2", () => {
    renderList("aB1", { ...DEFAULT_POLICY, password_min_uppercase: 2 });
    expect(screen.getByText(/at least 2 uppercase letters/i)).toBeInTheDocument();
  });
});

describe("meetsPolicy", () => {
  it("returns true when password satisfies every rule", () => {
    expect(meetsPolicy("Strong1ABC", DEFAULT_POLICY)).toBe(true);
  });

  it("returns false when any single rule fails", () => {
    expect(meetsPolicy("strong1ABC", { ...DEFAULT_POLICY, password_min_uppercase: 1 })).toBe(true);
    expect(meetsPolicy("strong1abc", DEFAULT_POLICY)).toBe(false); // no uppercase
    expect(meetsPolicy("Short1A", DEFAULT_POLICY)).toBe(false); // 7 chars (too short)
  });

  it("treats fully-disabled policy as always met", () => {
    const zero: PasswordPolicy = {
      password_min_length: 0,
      password_min_uppercase: 0,
      password_min_lowercase: 0,
      password_min_digits: 0,
      password_min_special: 0,
    };
    expect(meetsPolicy("", zero)).toBe(true);
  });
});
