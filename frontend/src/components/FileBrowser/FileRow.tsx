import { Box, Checkbox, Group, Table, Text } from "@mantine/core";
import { formatBytes } from "@/utils/formatBytes";
import { getFileIcon } from "@/utils/fileIcon";
import { FileRowActionsMenu } from "./FileRowActionsMenu";
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
        {/* Flex + truncate: the row height is a virtualization constant
            (ROW_HEIGHT=44), so names must NEVER wrap — a 4-line name on a
            narrow screen would overlap the rows below. Full name stays
            reachable via the native title tooltip. */}
        <Group gap={8} wrap="nowrap" miw={0}>
          {(() => {
            const { Icon: TypeIcon, color } = getFileIcon(
              file.name,
              file.is_directory,
            );
            return <TypeIcon size={16} style={{ flexShrink: 0, color }} />;
          })()}
          <Text span size="sm" truncate title={file.name} miw={0}>
            {file.name}
          </Text>
        </Group>
      </Table.Td>
      {/* Size + Modified hide below sm: with layout="fixed" their reserved
          widths (100+160) would starve the Name column to zero on phones.
          Must stay in sync with the matching visibleFrom on the Th cells. */}
      <Table.Td visibleFrom="sm">
        {!file.is_directory && (
          <Text size="xs" c="dimmed">
            {formatBytes(file.size)}
          </Text>
        )}
      </Table.Td>
      <Table.Td visibleFrom="sm">
        {file.last_modified && (
          <Text size="xs" c="dimmed">
            {formatDate(file.last_modified)}
          </Text>
        )}
      </Table.Td>
      <Table.Td className={classes.actions}>
        {/* Desktop: inline hover-reveal icons. Phones (<sm): a single ⋮ menu
            — four always-visible icons (no hover on touch) would starve the
            Name column. Width contract lives in .actionsCol. */}
        <Box visibleFrom="sm">
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
        </Box>
        <Box hiddenFrom="sm">
          <FileRowActionsMenu
            isDirectory={file.is_directory}
            canPreview={canPreview}
            filename={file.name}
            onDownload={() => onDownload(file.name)}
            onCopyUrl={() => onCopyUrl(file.name)}
            onPreview={() => onPreview(file.name)}
            onDelete={() => onDelete(file.name)}
            disabled={disableDeletion}
          />
        </Box>
      </Table.Td>
    </Table.Tr>
  );
}
