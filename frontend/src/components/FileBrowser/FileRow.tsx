import { Checkbox, Table, Text } from "@mantine/core";
import { File as FileIcon, Folder } from "lucide-react";
import { formatBytes } from "@/utils/formatBytes";
import { formatDate } from "@/utils/formatDate";
import { useMe } from "@/features/auth/hooks/useMe";
import { useConfig } from "@/hooks/useConfig";
import { getPreviewType } from "@/utils/filePreview";
import { FileActions } from "./FileActions";
import classes from "./FileBrowser.module.css";
import type { FileEntry } from "@/types/api";

// Only the first screenful of rows plays the staggered fade-in entry (cold-load
// delight). Rows past this — the tail of a large first page AND every
// lazy-revealed row — render instantly, so scrolling never waits on a per-row
// animation delay. Shared with FileCard (grid) so table and grid match.
export const STAGGER_ROW_LIMIT = 16;

interface FileRowProps {
  file: FileEntry;
  index: number;
  selected: boolean;
  /** `shiftKey` lets the parent implement range-select on Shift+click. */
  onToggleSelect: (name: string, shiftKey: boolean) => void;
  onNavigate: (folderName: string) => void;
  onDownload: (name: string) => void;
  onCopyUrl: (name: string) => void;
  onCopyUrlWithTtl?: (name: string, ttlSeconds: number) => void;
  onPreview: (name: string) => void;
  onDelete: (name: string) => void;
  /** Server default presigned TTL (seconds) — forwarded to FileActions. */
  defaultTtl?: number;
  /** Configured max presigned TTL (seconds) — forwarded to FileActions. */
  maxTtl?: number;
}

export function FileRow({
  file,
  index,
  selected,
  onToggleSelect,
  onNavigate,
  onDownload,
  onCopyUrl,
  onCopyUrlWithTtl,
  onPreview,
  onDelete,
  defaultTtl,
  maxTtl,
}: FileRowProps) {
  const me = useMe();
  const disableDeletion = me.data?.disable_deletion ?? false;
  const { data: config } = useConfig();
  const canPreview =
    !file.is_directory &&
    getPreviewType(file.name, config?.auto_inline_extensions ?? []) !== null;
  // Stagger only the first screenful; later / lazy-revealed rows appear instantly.
  const animateIn = index < STAGGER_ROW_LIMIT;
  // Zebra striping by ABSOLUTE row index (not Mantine's nth-child `striped`):
  // virtualization renders a shifting window with a spacer row, so nth-child
  // parity is unstable. Odd indices get the stripe — matches the look of the
  // former `striped="even"` (nth-of-type even == 0-indexed odd rows).
  const striped = index % 2 === 1;
  const rowClassName = [
    classes.row,
    animateIn && classes.animateIn,
    striped && classes.stripe,
  ]
    .filter(Boolean)
    .join(" ");

  return (
    <Table.Tr
      className={rowClassName}
      style={
        animateIn ? ({ "--row-index": index } as React.CSSProperties) : undefined
      }
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
          // Shift+click extends the browser's native text selection across the
          // rows being range-selected, which looks broken. Suppress only the
          // shift case so plain (no-shift) selection of filenames still works
          // for copy.
          onMouseDown={(e) => {
            if (e.shiftKey) e.preventDefault();
          }}
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
              color: "var(--mantine-primary-color-filled)",
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
          onCopyUrlWithTtl={
            onCopyUrlWithTtl ? (ttl) => onCopyUrlWithTtl(file.name, ttl) : undefined
          }
          onPreview={() => onPreview(file.name)}
          onDelete={() => onDelete(file.name)}
          disabled={disableDeletion}
          defaultTtl={defaultTtl}
          maxTtl={maxTtl}
        />
      </Table.Td>
    </Table.Tr>
  );
}
