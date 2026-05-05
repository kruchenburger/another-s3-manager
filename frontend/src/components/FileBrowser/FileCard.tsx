import { useState } from "react";
import { Card, Checkbox, Group, Text } from "@mantine/core";
import { File as FileIcon, Folder } from "lucide-react";
import { formatBytes } from "@/utils/formatBytes";
import { useMe } from "@/features/auth/hooks/useMe";
import { usePresignedUrl } from "@/features/files/hooks/usePresignedUrl";
import { joinPath } from "@/utils/pathUtils";
import { FileActions } from "./FileActions";
import classes from "./FileBrowser.module.css";
import type { FileEntry } from "@/types/api";

const PREVIEWABLE_RE = /\.(png|jpe?g|gif|webp|svg|mp4|webm|mov|pdf|txt|json|yaml|yml|log|md)$/i;
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
  onToggleSelect: (name: string) => void;
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

  return (
    <Card
      className={classes.row}
      style={{ "--row-index": index, position: "relative", cursor: file.is_directory ? "pointer" : "default" } as React.CSSProperties}
      onClick={() => file.is_directory && onNavigate(file.name)}
    >
      <Group justify="space-between" wrap="nowrap" mb="sm">
        <Checkbox
          checked={selected}
          onChange={() => onToggleSelect(file.name)}
          onClick={(e) => e.stopPropagation()}
          aria-label={`Select ${file.name}`}
        />
        <div className={classes.actions} onClick={(e) => e.stopPropagation()}>
          <FileActions
            isDirectory={file.is_directory}
            canPreview={canPreview}
            onDownload={() => onDownload(file.name)}
            onCopyUrl={() => onCopyUrl(file.name)}
            onPreview={() => onPreview(file.name)}
            onDelete={() => onDelete(file.name)}
            disabled={disableDeletion}
          />
        </div>
      </Group>
      <Group justify="center" mb="sm" style={{ minHeight: 48 }}>
        {file.is_directory ? (
          <Folder size={48} style={{ color: "var(--mantine-color-amber-6)" }} />
        ) : kind === "image" && presigned.data?.url && !mediaError ? (
          <img
            src={presigned.data.url}
            alt={file.name}
            loading="lazy"
            decoding="async"
            onError={() => setMediaError(true)}
            style={{ maxWidth: 48, maxHeight: 48, objectFit: "cover", borderRadius: 4 }}
          />
        ) : kind === "video" && presigned.data?.url && !mediaError ? (
          <video
            src={presigned.data.url}
            preload="metadata"
            muted
            playsInline
            onError={() => setMediaError(true)}
            style={{ maxWidth: 48, maxHeight: 48, objectFit: "cover", borderRadius: 4 }}
          />
        ) : (
          <FileIcon size={48} style={{ color: "var(--mantine-color-slate-5)" }} />
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
