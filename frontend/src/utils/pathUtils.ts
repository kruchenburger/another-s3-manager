/**
 * S3 keys are slash-delimited but each segment can contain reserved URL chars
 * (`:`, `#`, `?`, `&`, `=`, spaces, unicode). encodePath encodes per-segment
 * to keep `/` as the visual separator while making each segment URL-safe.
 */
export function encodePath(path: string): string {
  if (!path) return "";
  return path
    .split("/")
    .map(encodeURIComponent)
    .join("/");
}

export function decodePath(path: string): string {
  if (!path) return "";
  return path
    .split("/")
    .map(decodeURIComponent)
    .join("/");
}

export function joinPath(...segments: string[]): string {
  return segments
    .map((s) => s.replace(/^\/+|\/+$/g, ""))
    .filter((s) => s.length > 0)
    .join("/");
}

export function parentPath(path: string): string {
  const trimmed = path.replace(/\/+$/, "");
  const lastSlash = trimmed.lastIndexOf("/");
  if (lastSlash === -1) return "";
  return trimmed.slice(0, lastSlash);
}

export interface Crumb {
  name: string;
  path: string;
}

export function splitCrumbs(path: string): Crumb[] {
  if (!path) return [];
  const segments = path.split("/").filter(Boolean);
  return segments.map((name, i) => ({
    name,
    path: segments.slice(0, i + 1).join("/"),
  }));
}
