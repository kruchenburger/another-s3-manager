import { useState } from "react";
import { Card, Checkbox, Group, Text } from "@mantine/core";
import { File as FileIcon, Folder } from "lucide-react";
import { formatBytes } from "@/utils/formatBytes";
import { useMe } from "@/features/auth/hooks/useMe";
import { usePresignedUrl } from "@/features/files/hooks/usePresignedUrl";
import { joinPath } from "@/utils/pathUtils";
import { FileActions } from "./FileActions";
import { STAGGER_ROW_LIMIT } from "./FileRow";
import classes from "./FileBrowser.module.css";
import type { FileEntry } from "@/types/api";

const PREVIEWABLE_RE =
  /\.(png|jpe?g|gif|webp|svg|mp4|webm|mov|pdf|txt|json|yaml|yml|log|md)$/i;
const IMAGE_RE = /\.(png|jpe?g|gif|webp|svg)$/i;
const VIDEO_RE = /\.(mp4|webm|mov)$/i;

type PreviewKind = "image" | "video" | "other";

function categorizePreview(name: string): PreviewKind {
  if (IMAGE_RE.test(name)) return "image";
  if (VIDEO_RE.test(name)) return "video";
  return "other";
}

interface FileCardProps {
  file: FileEntry;
  index: number;
  selected: boolean;
  /** `shiftKey` lets the parent implement range-select on Shift+click. */
  onToggleSelect: (name: string, shiftKey: boolean) => void;
  onNavigate: (folderName: string) => void;
  onDownload: (name: string) => void;
  onCopyUrl: (name: string) => void;
  onPreview: (name: string) => void;
  onDelete: (name: string) => void;
  bucket: string;
  roleId: string;
  /** Current folder prefix (without trailing slash). */
  path: string;
}

export function FileCard({
  file,
  index,
  selected,
  onToggleSelect,
  onNavigate,
  onDownload,
  onCopyUrl,
  onPreview,
  onDelete,
  bucket,
  roleId,
  path,
}: FileCardProps) {
  const me = useMe();
  const disableDeletion = me.data?.disable_deletion ?? false;
  const canPreview = !file.is_directory && PREVIEWABLE_RE.test(file.name);
  const kind = file.is_directory ? "other" : categorizePreview(file.name);
  const fullPath = joinPath(path, file.name);
  const enabled = !file.is_directory && (kind === "image" || kind === "video");
  const presigned = usePresignedUrl(bucket, roleId, fullPath, enabled);
  const [mediaError, setMediaError] = useState(false);
  // Stagger only the first screenful; later / lazy-revealed cards appear instantly.
  const animateIn = index < STAGGER_ROW_LIMIT;

  return (
    <Card
      className={animateIn ? `${classes.row} ${classes.animateIn}` : classes.row}
      style={
        {
          ...(animateIn ? { "--row-index": index } : {}),
          position: "relative",
          cursor: file.is_directory ? "pointer" : "default",
        } as React.CSSProperties
      }
      onClick={() => file.is_directory && onNavigate(file.name)}
    >
      <Group justify="space-between" wrap="nowrap" mb="sm">
        <Checkbox
          checked={selected}
          onChange={(e) => {
            // See FileRow.tsx for the same cast — React.ChangeEvent's
            // nativeEvent type doesn't expose shiftKey.
            const native = e.nativeEvent as MouseEvent | KeyboardEvent;
            onToggleSelect(file.name, native.shiftKey ?? false);
          }}
          onClick={(e) => e.stopPropagation()}
          aria-label={`Select ${file.name}`}
        />
        <div className={classes.actions} onClick={(e) => e.stopPropagation()}>
          <FileActions
            isDirectory={file.is_directory}
            canPreview={canPreview}
            filename={file.name}
            onDownload={() => onDownload(file.name)}
            onCopyUrl={() => onCopyUrl(file.name)}
            onPreview={() => onPreview(file.name)}
            onDelete={() => onDelete(file.name)}
            disabled={disableDeletion}
          />
        </div>
      </Group>
      {/* Central preview/icon area. mih matches the max thumbnail size
          (120px in FileBrowser.module.css) so every card in a grid row
          reserves the same vertical space whether it shows a 120px image
          thumbnail, a 64px Lucide icon, or nothing yet (presigned URL
          still loading). Without matching mih, folders/icon-fallback
          cards looked compact while neighbouring thumbnail cards were
          tall — visible layout drift in mixed grid rows.

          Icons stay at 64px (not 120px): Lucide line icons render best
          at small/medium sizes; 120px would make them look like
          oversized stickers. Centering inside the 120px box keeps the
          visual centerline consistent across all card types. */}
      <Group justify="center" align="center" mb="sm" mih={120}>
        {file.is_directory ? (
          <Folder
            size={64}
            style={{ color: "var(--mantine-primary-color-filled)" }}
          />
        ) : kind === "image" && presigned.data?.url && !mediaError ? (
          <img
            src={presigned.data.url}
            alt={file.name}
            loading="lazy"
            decoding="async"
            onError={() => setMediaError(true)}
            className={classes.thumbnail}
          />
        ) : kind === "video" && presigned.data?.url && !mediaError ? (
          <video
            src={presigned.data.url}
            preload="metadata"
            muted
            playsInline
            onError={() => setMediaError(true)}
            className={classes.thumbnail}
          />
        ) : (
          <FileIcon
            size={64}
            style={{ color: "var(--mantine-color-slate-5)" }}
          />
        )}
      </Group>
      <Text size="sm" ta="center" lineClamp={2} title={file.name}>
        {file.name}
      </Text>
      {!file.is_directory && (
        <Text size="xs" c="dimmed" ta="center">
          {formatBytes(file.size)}
        </Text>
      )}
    </Card>
  );
}
