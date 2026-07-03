import { type RefObject } from "react";
import { Checkbox, Table } from "@mantine/core";
import { useVirtualizer } from "@tanstack/react-virtual";
import type { FileEntry } from "@/types/api";
import { FileRow } from "./FileRow";
import { useNearEndAutoLoad } from "./useNearEndAutoLoad";
import classes from "./FileBrowser.module.css";

interface FileTableProps {
  files: FileEntry[];
  selected: Set<string>;
  onToggleSelect: (name: string, shiftKey: boolean) => void;
  onToggleSelectAll: () => void;
  onNavigate: (name: string) => void;
  onDownload: (name: string) => void;
  onCopyUrl: (name: string) => void;
  onCopyUrlWithTtl?: (name: string, ttlSeconds: number) => void;
  onPreview: (name: string) => void;
  onDelete: (name: string) => void;
  /** Server default presigned TTL (seconds) — forwarded to FileRow → FileActions. */
  defaultTtl?: number;
  /** Configured max presigned TTL (seconds) — forwarded to FileRow → FileActions. */
  maxTtl?: number;
  /** The FileBrowser internal scroll container the virtualizer measures. */
  scrollRef: RefObject<HTMLDivElement | null>;
  /** lazy && truncated && !isFetchingNextPage && !searching (computed by parent). */
  autoLoadEnabled: boolean;
  /** Fetch the next server chunk. */
  onLoadMore: () => void;
}

// Fixed row height (px). Matches Table verticalSpacing="xs" single-line rows.
// The explicit verticalSpacing="xs" below is deliberate: the theme default
// moved to "sm" (airify), but this table is virtualized against ROW_HEIGHT —
// change both together or rows will overlap/gap.
const ROW_HEIGHT = 44;

// Number of columns in the table (checkbox, name, size, modified, actions).
const TABLE_COLUMN_COUNT = 5;

export function FileTable({
  files,
  selected,
  onToggleSelect,
  onToggleSelectAll,
  onNavigate,
  onDownload,
  onCopyUrl,
  onCopyUrlWithTtl,
  onPreview,
  onDelete,
  defaultTtl,
  maxTtl,
  scrollRef,
  autoLoadEnabled,
  onLoadMore,
}: FileTableProps) {
  const allSelected =
    files.length > 0 && files.every((f) => selected.has(f.name));
  const someSelected = files.some((f) => selected.has(f.name)) && !allSelected;

  const virtualizer = useVirtualizer({
    count: files.length,
    getScrollElement: () => scrollRef.current,
    estimateSize: () => ROW_HEIGHT,
    overscan: 8,
  });

  useNearEndAutoLoad(virtualizer, files.length, autoLoadEnabled, onLoadMore);

  const virtualRows = virtualizer.getVirtualItems();
  const totalSize = virtualizer.getTotalSize();
  const paddingTop = virtualRows.length ? virtualRows[0].start : 0;
  const paddingBottom = virtualRows.length
    ? totalSize - virtualRows[virtualRows.length - 1].end
    : 0;

  return (
    // No Mantine `striped` prop: it stripes by DOM `:nth-child`, which is wrong
    // under virtualization — the variable-height top spacer <tr> plus the
    // shifting render window flip every row's nth-child parity as you scroll (and
    // all at once when a chunk appends), so the zebra bands visibly flicker.
    // FileRow stripes itself by absolute row index instead (stable per row).
    <Table verticalSpacing="xs">
      <Table.Thead className={classes.stickyHead}>
        <Table.Tr>
          <Table.Th style={{ width: 40 }}>
            <Checkbox
              checked={allSelected}
              indeterminate={someSelected}
              onChange={onToggleSelectAll}
              aria-label="Select all"
            />
          </Table.Th>
          <Table.Th>Name</Table.Th>
          <Table.Th style={{ width: 100 }}>Size</Table.Th>
          <Table.Th style={{ width: 160 }}>Modified</Table.Th>
          <Table.Th style={{ width: 180 }}>Actions</Table.Th>
        </Table.Tr>
      </Table.Thead>
      <Table.Tbody>
        {paddingTop > 0 && (
          <Table.Tr data-spacer aria-hidden>
            <Table.Td colSpan={TABLE_COLUMN_COUNT} style={{ height: paddingTop, padding: 0, border: 0 }} />
          </Table.Tr>
        )}
        {virtualRows.map((vrow) => {
          const file = files[vrow.index];
          return (
            <FileRow
              key={file.name}
              file={file}
              index={vrow.index}
              selected={selected.has(file.name)}
              onToggleSelect={onToggleSelect}
              onNavigate={onNavigate}
              onDownload={onDownload}
              onCopyUrl={onCopyUrl}
              onCopyUrlWithTtl={onCopyUrlWithTtl}
              onPreview={onPreview}
              onDelete={onDelete}
              defaultTtl={defaultTtl}
              maxTtl={maxTtl}
            />
          );
        })}
        {paddingBottom > 0 && (
          <Table.Tr data-spacer aria-hidden>
            <Table.Td colSpan={TABLE_COLUMN_COUNT} style={{ height: paddingBottom, padding: 0, border: 0 }} />
          </Table.Tr>
        )}
      </Table.Tbody>
    </Table>
  );
}
