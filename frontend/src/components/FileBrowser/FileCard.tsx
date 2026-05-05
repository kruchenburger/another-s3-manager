import { Card, Checkbox, Group, Text } from "@mantine/core";
import { File as FileIcon, Folder } from "lucide-react";
import { formatBytes } from "@/utils/formatBytes";
import { useMe } from "@/features/auth/hooks/useMe";
import { FileActions } from "./FileActions";
import classes from "./FileBrowser.module.css";
import type { FileEntry } from "@/types/api";

const PREVIEWABLE_RE = /\.(png|jpe?g|gif|webp|svg|mp4|webm|mov|pdf|txt|json|yaml|yml|log|md)$/i;

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
}: FileCardProps) {
  const me = useMe();
  const disableDeletion = me.data?.disable_deletion ?? false;
  const canPreview = !file.is_directory && PREVIEWABLE_RE.test(file.name);

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
      <Group justify="center" mb="sm">
        {file.is_directory ? (
          <Folder size={48} style={{ color: "var(--mantine-color-amber-6)" }} />
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
