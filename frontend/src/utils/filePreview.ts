// Single source of truth for "can this file be previewed, and how".
// Media (images / video / pdf) are ALWAYS previewable — built-in viewers,
// independent of admin config. Text preview is driven by the admin
// `auto_inline_extensions` list; when that list is empty we fall back to a
// sensible default set so the out-of-the-box experience still previews common
// text files (matches the pre-config hardcoded behaviour).

export type PreviewType = "image" | "video" | "pdf" | "text" | null;

const IMAGE_EXTS = ["png", "jpg", "jpeg", "gif", "webp", "svg"];
const VIDEO_EXTS = ["mp4", "webm", "mov"];

// Fallback text extensions when the admin hasn't configured auto_inline_extensions.
// Mirrors the old hardcoded preview lists.
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
  const textExts = autoInlineExts.length > 0 ? autoInlineExts : DEFAULT_TEXT_EXTS;
  if (textExts.includes(ext)) return "text";
  return null;
}
