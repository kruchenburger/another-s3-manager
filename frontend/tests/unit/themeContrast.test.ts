import { describe, expect, it } from "vitest";
import { coralRed, dark, SURFACE_DARK } from "@/app/theme";

// WCAG 2.1 relative luminance + contrast ratio. Guards the airify palette:
// if live tuning nudges a shade below AA, this fails before axe ever runs.
function srgbChannel(c: number): number {
  const s = c / 255;
  return s <= 0.04045 ? s / 12.92 : ((s + 0.055) / 1.055) ** 2.4;
}

function luminance(hex: string): number {
  const m = /^#([0-9a-f]{6})$/i.exec(hex.trim());
  if (!m) throw new Error(`expected 6-digit hex, got: ${hex}`);
  const n = Number.parseInt(m[1], 16);
  return (
    0.2126 * srgbChannel((n >> 16) & 0xff) +
    0.7152 * srgbChannel((n >> 8) & 0xff) +
    0.0722 * srgbChannel(n & 0xff)
  );
}

function contrast(a: string, b: string): number {
  const [hi, lo] = [luminance(a), luminance(b)].sort((x, y) => y - x);
  return (hi + 0.05) / (lo + 0.05);
}

const BODY_DARK = dark[7]; // --mantine-color-body in dark scheme
const BODY_LIGHT = "#f5f7fa"; // resolver light --mantine-color-body

describe("airify palette contrast guards (WCAG AA)", () => {
  it("dimmed text (dark.2) >= 4.5:1 on body and elevated surface", () => {
    expect(contrast(dark[2], BODY_DARK)).toBeGreaterThanOrEqual(4.5);
    expect(contrast(dark[2], SURFACE_DARK)).toBeGreaterThanOrEqual(4.5);
  });

  it("primary text (dark.0) >= 7:1 on body and elevated surface", () => {
    expect(contrast(dark[0], BODY_DARK)).toBeGreaterThanOrEqual(7);
    expect(contrast(dark[0], SURFACE_DARK)).toBeGreaterThanOrEqual(7);
  });

  it("dark-scheme error text (red.5) >= 4.5:1 on dark body", () => {
    expect(contrast(coralRed[5], BODY_DARK)).toBeGreaterThanOrEqual(4.5);
  });

  it("light-scheme error text (red.8) >= 4.5:1 on light body", () => {
    expect(contrast(coralRed[8], BODY_LIGHT)).toBeGreaterThanOrEqual(4.5);
  });

  it("coral controls (red.6) >= 3:1 UI-component contrast on dark body", () => {
    expect(contrast(coralRed[6], BODY_DARK)).toBeGreaterThanOrEqual(3);
  });
});
