import { Checkbox, Table, Text } from "@mantine/core";
import { File as FileIcon, Folder } from "lucide-react";
import { formatBytes } from "@/utils/formatBytes";
import { formatDate } from "@/utils/formatDate";
import { FileActions } from "./FileActions";
import classes from "./FileBrowser.module.css";
import type { FileEntry } from "@/types/api";

interface FileRowProps {
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

const PREVIEWABLE_RE = /\.(png|jpe?g|gif|webp|svg|mp4|webm|mov|pdf|txt|json|yaml|yml|log|md)$/i;

export function FileRow({
  file,
  index,
  selected,
  onToggleSelect,
  onNavigate,
  onDownload,
  onCopyUrl,
  onPreview,
  onDelete,
}: FileRowProps) {
  const canPreview = !file.is_directory && PREVIEWABLE_RE.test(file.name);

  return (
    <Table.Tr
      className={classes.row}
      style={{ "--row-index": index } as React.CSSProperties}
      onDoubleClick={() => file.is_directory && onNavigate(file.name)}
    >
      <Table.Td>
        <Checkbox
          checked={selected}
          onChange={() => onToggleSelect(file.name)}
          aria-label={`Select ${file.name}`}
          onClick={(e) => e.stopPropagation()}
        />
      </Table.Td>
      <Table.Td
        style={{ cursor: file.is_directory ? "pointer" : "default" }}
        onClick={() => file.is_directory && onNavigate(file.name)}
      >
        {file.is_directory ? (
          <Folder size={16} style={{ verticalAlign: "middle", marginRight: 8, color: "var(--mantine-color-amber-6)" }} />
        ) : (
          <FileIcon size={16} style={{ verticalAlign: "middle", marginRight: 8, color: "var(--mantine-color-slate-5)" }} />
        )}
        <Text span size="sm">{file.name}</Text>
      </Table.Td>
      <Table.Td>
        {!file.is_directory && (
          <Text size="xs" c="dimmed">{formatBytes(file.size)}</Text>
        )}
      </Table.Td>
      <Table.Td>
        {file.last_modified && (
          <Text size="xs" c="dimmed">{formatDate(file.last_modified)}</Text>
        )}
      </Table.Td>
      <Table.Td className={classes.actions}>
        <FileActions
          isDirectory={file.is_directory}
          canPreview={canPreview}
          onDownload={() => onDownload(file.name)}
          onCopyUrl={() => onCopyUrl(file.name)}
          onPreview={() => onPreview(file.name)}
          onDelete={() => onDelete(file.name)}
        />
      </Table.Td>
    </Table.Tr>
  );
}
