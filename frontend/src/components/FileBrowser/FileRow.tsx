import { Checkbox, Table, Text } from "@mantine/core";
import { File as FileIcon, Folder } from "lucide-react";
import { formatBytes } from "@/utils/formatBytes";
import { formatDate } from "@/utils/formatDate";
import { useMe } from "@/features/auth/hooks/useMe";
import { FileActions } from "./FileActions";
import classes from "./FileBrowser.module.css";
import type { FileEntry } from "@/types/api";

interface FileRowProps {
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
}

const PREVIEWABLE_RE =
  /\.(png|jpe?g|gif|webp|svg|mp4|webm|mov|pdf|txt|json|yaml|yml|log|md)$/i;

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
  const me = useMe();
  const disableDeletion = me.data?.disable_deletion ?? false;
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
          onChange={(e) => {
            // React.ChangeEvent.nativeEvent is typed as the generic DOM
            // `Event` (no shiftKey). At runtime, a checkbox onChange fires
            // from either a mouse click (MouseEvent) or keyboard activation
            // (KeyboardEvent) — both have shiftKey. Narrow the type so
            // tsc -b is happy and degrade safely to `false` if nativeEvent
            // is somehow neither (programmatic toggle, etc.).
            const native = e.nativeEvent as MouseEvent | KeyboardEvent;
            onToggleSelect(file.name, native.shiftKey ?? false);
          }}
          aria-label={`Select ${file.name}`}
          onClick={(e) => e.stopPropagation()}
        />
      </Table.Td>
      <Table.Td
        style={{ cursor: file.is_directory ? "pointer" : "default" }}
        onClick={() => file.is_directory && onNavigate(file.name)}
      >
        {file.is_directory ? (
          <Folder
            size={16}
            style={{
              verticalAlign: "middle",
              marginRight: 8,
              color: "var(--mantine-color-amber-6)",
            }}
          />
        ) : (
          <FileIcon
            size={16}
            style={{
              verticalAlign: "middle",
              marginRight: 8,
              color: "var(--mantine-color-slate-5)",
            }}
          />
        )}
        <Text span size="sm">
          {file.name}
        </Text>
      </Table.Td>
      <Table.Td>
        {!file.is_directory && (
          <Text size="xs" c="dimmed">
            {formatBytes(file.size)}
          </Text>
        )}
      </Table.Td>
      <Table.Td>
        {file.last_modified && (
          <Text size="xs" c="dimmed">
            {formatDate(file.last_modified)}
          </Text>
        )}
      </Table.Td>
      <Table.Td className={classes.actions}>
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
      </Table.Td>
    </Table.Tr>
  );
}
