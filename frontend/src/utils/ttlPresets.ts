import { formatDuration } from "./formatDuration";

export interface TtlPreset {
  /** TTL in seconds. */
  value: number;
  /** Human label, e.g. "6 hours". */
  label: string;
}

/** Canonical presigned-URL validity presets, ascending. */
export const TTL_PRESETS: TtlPreset[] = [
  { value: 300, label: formatDuration(300) }, // 5 minutes
  { value: 900, label: formatDuration(900) }, // 15 minutes
  { value: 3600, label: formatDuration(3600) }, // 1 hour
  { value: 21600, label: formatDuration(21600) }, // 6 hours
  { value: 43200, label: formatDuration(43200) }, // 12 hours
  { value: 86400, label: formatDuration(86400) }, // 24 hours
  { value: 259200, label: formatDuration(259200) }, // 3 days
  { value: 604800, label: formatDuration(604800) }, // 7 days
];

/** Presets with value ≤ maxTtl. */
export function ttlOptionsUpTo(maxTtl: number): TtlPreset[] {
  return TTL_PRESETS.filter((p) => p.value <= maxTtl);
}

/** Mantine Select data (string values) for presets ≤ maxTtl. */
export function ttlSelectDataUpTo(maxTtl: number): { value: string; label: string }[] {
  return ttlOptionsUpTo(maxTtl).map((p) => ({ value: String(p.value), label: p.label }));
}

/**
 * Ensure `value` (seconds) is selectable in the given Mantine Select data.
 * If it isn't a known preset (e.g. a hand-edited config value), inject a
 * "Custom (…)" option so the field never silently drops the stored value.
 * Result stays sorted ascending by numeric value.
 */
export function withConfiguredValue(
  data: { value: string; label: string }[],
  value: number,
): { value: string; label: string }[] {
  if (data.some((d) => d.value === String(value))) return data;
  const injected = [...data, { value: String(value), label: `Custom (${formatDuration(value)})` }];
  return injected.sort((a, b) => Number(a.value) - Number(b.value));
}
