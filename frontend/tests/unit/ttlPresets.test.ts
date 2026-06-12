import { describe, expect, it } from "vitest";
import {
  TTL_PRESETS,
  ttlOptionsUpTo,
  ttlSelectDataUpTo,
  withConfiguredValue,
} from "@/utils/ttlPresets";

describe("ttlPresets", () => {
  it("has ascending preset values", () => {
    const values = TTL_PRESETS.map((p) => p.value);
    expect(values).toEqual([...values].sort((a, b) => a - b));
  });

  it("ttlOptionsUpTo filters out presets above the max", () => {
    const opts = ttlOptionsUpTo(3600);
    expect(opts.every((p) => p.value <= 3600)).toBe(true);
    expect(opts.map((p) => p.value)).toContain(3600);
    expect(opts.map((p) => p.value)).not.toContain(21600);
  });

  it("ttlSelectDataUpTo returns string-valued Mantine data", () => {
    const data = ttlSelectDataUpTo(3600);
    expect(data[0]).toHaveProperty("value");
    expect(typeof data[0].value).toBe("string");
  });

  it("withConfiguredValue injects a Custom option for a non-preset value", () => {
    const data = withConfiguredValue(ttlSelectDataUpTo(604800), 5400);
    const match = data.find((d) => d.value === "5400");
    expect(match).toBeDefined();
    expect(match!.label).toContain("Custom");
  });

  it("withConfiguredValue does not duplicate an existing preset value", () => {
    const data = withConfiguredValue(ttlSelectDataUpTo(604800), 3600);
    const matches = data.filter((d) => d.value === "3600");
    expect(matches).toHaveLength(1);
  });
});
