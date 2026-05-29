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
  hasNextPage: boolean;
  isFetchingNextPage: boolean;
  onLoadMore: () => void;
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
  hasNextPage,
  isFetchingNextPage,
  onLoadMore,
  lazyLoadingEnabled,
}: FileTableProps) {
  const allSelected =
    files.length > 0 && files.every((f) => selected.has(f.name));
  const someSelected = files.some((f) => selected.has(f.name)) && !allSelected;

  // Sentinel that fires onLoadMore when scrolled into view, mounted only when
  // lazy loading is enabled. rootMargin=100px so the next page starts loading
  // before the user actually hits the bottom — feels seamless on fast networks.
  const { ref: sentinelRef, inView } = useInView({ rootMargin: "100px" });

  useEffect(() => {
    if (lazyLoadingEnabled && hasNextPage && inView && !isFetchingNextPage) {
      onLoadMore();
    }
  }, [
    lazyLoadingEnabled,
    hasNextPage,
    inView,
    isFetchingNextPage,
    onLoadMore,
  ]);

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
      {hasNextPage && (
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
                <Button
                  variant="subtle"
                  onClick={onLoadMore}
                  loading={isFetchingNextPage}
                >
                  Load more
                </Button>
              )}
            </Table.Td>
          </Table.Tr>
        </Table.Tfoot>
      )}
    </Table>
  );
}
