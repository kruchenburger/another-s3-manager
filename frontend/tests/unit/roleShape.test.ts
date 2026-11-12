import { describe, expect, it } from "vitest";
import { roleAllowsDelete } from "@/features/admin/api/roleShape";

describe("roleAllowsDelete", () => {
  it("allows an absent field", () => {
    expect(roleAllowsDelete({})).toBe(true);
  });
  it.each([[true, true], [false, false], [undefined, false], [null, false], ["true", false], ["false", false], [1, false], [0, false]])(
    "decodes explicit %s without coercion", (value, expected) => {
      expect(roleAllowsDelete({ allow_delete: value })).toBe(expected);
    },
  );
});
