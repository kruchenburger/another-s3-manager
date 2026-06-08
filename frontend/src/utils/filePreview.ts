// Single source of truth for "can this file be previewed, and how".
// Media (images / video / pdf) are ALWAYS previewable — built-in viewers,
// independent of admin config. The built-in text extensions below are ALSO
// always previewable; the admin `auto_inline_extensions` list ADDS to them
// rather than replacing — so adding a custom extension (e.g. `ts`) never hides
// the common defaults like `.txt` / `.md` / `.json`.

export type PreviewType = "image" | "video" | "pdf" | "text" | null;

const IMAGE_EXTS = ["png", "jpg", "jpeg", "gif", "webp", "svg"];
const VIDEO_EXTS = ["mp4", "webm", "mov"];

// Built-in text extensions, always previewable regardless of admin config.
// The admin `auto_inline_extensions` setting is additive on top of these.
export const DEFAULT_TEXT_EXTS = ["txt", "md", "json", "yaml", "yml", "log", "csv"];

export function getPreviewType(
  filename: string,
  autoInlineExts: string[],
): PreviewType {
  const ext = filename.toLowerCase().split(".").pop() ?? "";
  if (ext === "") return null;
  if (IMAGE_EXTS.includes(ext)) return "image";
  if (VIDEO_EXTS.includes(ext)) return "video";
  if (ext === "pdf") return "pdf";
  // Defaults are always on; the admin list extends them (union, not replace).
  if (DEFAULT_TEXT_EXTS.includes(ext) || autoInlineExts.includes(ext)) {
    return "text";
  }
  return null;
}
