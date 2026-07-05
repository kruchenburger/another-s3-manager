import {
  Braces,
  Code,
  Database,
  File,
  FileText,
  Folder,
  Image,
  Music,
  Package,
  Video,
  type LucideIcon,
} from "lucide-react";

export interface FileIconSpec {
  Icon: LucideIcon;
  /** CSS color for the icon; undefined = inherit (deliberately untinted). */
  color?: string;
}

// Tint families re-picked after the airify palette: the 2026-05-20 critique
// used orange for archives, but airify re-tuned orange/yellow to ONE gold
// family — archives moved to indigo so they stay distinct from json/yaml.
// Tints are decorative; type is still conveyed by the file name.
const TINT = {
  image: "var(--mantine-color-teal-5)",
  video: "var(--mantine-color-pink-5)",
  audio: "var(--mantine-color-grape-5)",
  structured: "var(--mantine-color-yellow-6)", // airify gold
  data: "var(--mantine-color-cyan-5)",
  code: "var(--mantine-color-blue-5)",
  archive: "var(--mantine-color-indigo-4)",
} as const;

const EXT_MAP: Record<string, FileIconSpec> = {
  // images
  png: { Icon: Image, color: TINT.image },
  jpg: { Icon: Image, color: TINT.image },
  jpeg: { Icon: Image, color: TINT.image },
  gif: { Icon: Image, color: TINT.image },
  webp: { Icon: Image, color: TINT.image },
  svg: { Icon: Image, color: TINT.image },
  avif: { Icon: Image, color: TINT.image },
  // video
  mp4: { Icon: Video, color: TINT.video },
  webm: { Icon: Video, color: TINT.video },
  mov: { Icon: Video, color: TINT.video },
  mkv: { Icon: Video, color: TINT.video },
  // audio
  mp3: { Icon: Music, color: TINT.audio },
  flac: { Icon: Music, color: TINT.audio },
  wav: { Icon: Music, color: TINT.audio },
  ogg: { Icon: Music, color: TINT.audio },
  // structured config/data
  json: { Icon: Braces, color: TINT.structured },
  yaml: { Icon: Braces, color: TINT.structured },
  yml: { Icon: Braces, color: TINT.structured },
  toml: { Icon: Braces, color: TINT.structured },
  // tabular / db
  csv: { Icon: Database, color: TINT.data },
  tsv: { Icon: Database, color: TINT.data },
  sql: { Icon: Database, color: TINT.data },
  parquet: { Icon: Database, color: TINT.data },
  // code
  ts: { Icon: Code, color: TINT.code },
  tsx: { Icon: Code, color: TINT.code },
  js: { Icon: Code, color: TINT.code },
  jsx: { Icon: Code, color: TINT.code },
  py: { Icon: Code, color: TINT.code },
  go: { Icon: Code, color: TINT.code },
  rs: { Icon: Code, color: TINT.code },
  sh: { Icon: Code, color: TINT.code },
  // archives
  zip: { Icon: Package, color: TINT.archive },
  tar: { Icon: Package, color: TINT.archive },
  gz: { Icon: Package, color: TINT.archive },
  tgz: { Icon: Package, color: TINT.archive },
  bz2: { Icon: Package, color: TINT.archive },
  xz: { Icon: Package, color: TINT.archive },
  zst: { Icon: Package, color: TINT.archive },
  "7z": { Icon: Package, color: TINT.archive },
  rar: { Icon: Package, color: TINT.archive },
  // plain text — untinted on purpose (the most common type stays quiet)
  md: { Icon: FileText },
  txt: { Icon: FileText },
  log: { Icon: FileText },
};

export function getFileIcon(name: string, isDirectory: boolean): FileIconSpec {
  if (isDirectory) {
    // Folders are the wayfinding primitive — they get the project accent.
    return { Icon: Folder, color: "var(--mantine-color-mutedSlateBlue-6)" };
  }
  const dot = name.lastIndexOf(".");
  // No dot, or dot-first (".env", "README") → neutral fallback.
  const ext = dot > 0 ? name.slice(dot + 1).toLowerCase() : "";
  return EXT_MAP[ext] ?? { Icon: File, color: "var(--mantine-color-slate-5)" };
}
