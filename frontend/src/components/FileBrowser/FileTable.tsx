import { useEffect } from "react";
import { Button, Checkbox, Table } from "@mantine/core";
import { useInView } from "react-intersection-observer";
import type { FileEntry } from "@/types/api";
import { FileRow } from "./FileRow";

interface FileTableProps {
  files: FileEntry[];
  selected: Set<string>;
  onToggleSelect: (name: string, shiftKey: boolean) => void;
  onToggleSelectAll: () => void;
  onNavigate: (name: string) => void;
  onDownload: (name: string) => void;
  onCopyUrl: (name: string) => void;
  onPreview: (name: string) => void;
  onDelete: (name: string) => void;
  hasMoreInMemory: boolean;
  onRevealMore: () => void;
  lazyLoadingEnabled: boolean;
}

const TABLE_COLUMN_COUNT = 5;

export function FileTable({
  files,
  selected,
  onToggleSelect,
  onToggleSelectAll,
  onNavigate,
  onDownload,
  onCopyUrl,
  onPreview,
  onDelete,
  hasMoreInMemory,
  onRevealMore,
  lazyLoadingEnabled,
}: FileTableProps) {
  const allSelected =
    files.length > 0 && files.every((f) => selected.has(f.name));
  const someSelected = files.some((f) => selected.has(f.name)) && !allSelected;

  // Sentinel that reveals the next in-memory slice when scrolled into view,
  // mounted only when lazy loading is enabled. The generous bottom rootMargin
  // preloads the next slice ~a screenful before the user reaches the end, so
  // lazy reveal feels like a seamless infinite scroll instead of visibly
  // stalling at the bottom. This is the IntersectionObserver equivalent of the
  // vanilla UI, which triggers loadMore at 80% scrolled.
  const { ref: sentinelRef, inView } = useInView({
    rootMargin: "0px 0px 800px 0px",
  });

  // In-memory slice growth — instant, no network, no loader (rows already in
  // memory). Auto-reveal on scroll when lazy loading is on, else a Show more button.
  useEffect(() => {
    if (lazyLoadingEnabled && hasMoreInMemory && inView) {
      onRevealMore();
    }
  }, [lazyLoadingEnabled, hasMoreInMemory, inView, onRevealMore]);

  return (
    <Table highlightOnHover striped="even" verticalSpacing="xs">
      <Table.Thead>
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
        {files.map((file, i) => (
          <FileRow
            key={file.name}
            file={file}
            index={i}
            selected={selected.has(file.name)}
            onToggleSelect={onToggleSelect}
            onNavigate={onNavigate}
            onDownload={onDownload}
            onCopyUrl={onCopyUrl}
            onPreview={onPreview}
            onDelete={onDelete}
          />
        ))}
      </Table.Tbody>
      {hasMoreInMemory && (
        <Table.Tfoot>
          <Table.Tr>
            <Table.Td
              colSpan={TABLE_COLUMN_COUNT}
              style={{
                textAlign: "center",
                padding: "var(--mantine-spacing-md)",
              }}
            >
              {lazyLoadingEnabled ? (
                <div ref={sentinelRef} aria-hidden style={{ height: 1 }} />
              ) : (
                <Button variant="subtle" onClick={onRevealMore}>
                  Show more
                </Button>
              )}
            </Table.Td>
          </Table.Tr>
        </Table.Tfoot>
      )}
    </Table>
  );
}
