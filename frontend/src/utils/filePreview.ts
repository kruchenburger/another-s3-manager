// Single source of truth for "can this file be previewed, and how".
// Media (images / video / pdf) are ALWAYS previewable — built-in viewers,
// independent of admin config. Text preview is driven ENTIRELY by the admin
// `preview_text_extensions` list (stored in config.json): a file previews as
// text iff its extension is in that list. The list is seeded with sensible text
// defaults on the backend and is fully admin-owned — editing or clearing it
// changes exactly which text files preview, with no hidden fallback.
//
// Separate from `upload_inline_extensions` (which sets Content-Disposition on
// upload) — preview is a UI concern; that is an S3-object concern.

export type PreviewType = "image" | "video" | "pdf" | "text" | null;

const IMAGE_EXTS = ["png", "jpg", "jpeg", "gif", "webp", "svg"];
const VIDEO_EXTS = ["mp4", "webm", "mov"];

export function getPreviewType(
  filename: string,
  previewTextExts: string[],
): PreviewType {
  const ext = filename.toLowerCase().split(".").pop() ?? "";
  if (ext === "") return null;
  if (IMAGE_EXTS.includes(ext)) return "image";
  if (VIDEO_EXTS.includes(ext)) return "video";
  if (ext === "pdf") return "pdf";
  // Text is purely list-driven — no hidden defaults. The list itself carries
  // the defaults (seeded server-side) and is what the admin edits/clears.
  if (previewTextExts.includes(ext)) return "text";
  return null;
}
