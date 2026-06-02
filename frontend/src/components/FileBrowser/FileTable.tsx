import { useEffect } from "react";
import { Button, Center, Checkbox, Loader, Table, Text } from "@mantine/core";
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
  hasMore: boolean;
  isFetchingMore: boolean;
  onReachEnd: () => void;
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
  hasMore,
  isFetchingMore,
  onReachEnd,
  lazyLoadingEnabled,
}: FileTableProps) {
  const allSelected =
    files.length > 0 && files.every((f) => selected.has(f.name));
  const someSelected = files.some((f) => selected.has(f.name)) && !allSelected;

  // Sentinel that drives the next reveal/fetch when scrolled into view,
  // mounted only when lazy loading is enabled. rootMargin=100px so the next
  // rows appear before the user actually hits the bottom.
  const { ref: sentinelRef, inView } = useInView({ rootMargin: "100px" });

  // Continuous reveal: while the sentinel is visible and there's more to show,
  // keep asking the parent to reveal/fetch. Depending on files.length re-runs
  // this after each reveal grows the list — so one scroll-to-bottom cascades
  // through the whole in-memory set instead of stalling after one step.
  useEffect(() => {
    if (lazyLoadingEnabled && hasMore && inView && !isFetchingMore) {
      onReachEnd();
    }
  }, [lazyLoadingEnabled, hasMore, inView, isFetchingMore, files.length, onReachEnd]);

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
      {hasMore && (
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
                isFetchingMore ? (
                  <Center>
                    <Loader size="sm" />
                    <Text size="sm" c="dimmed" ml="xs">
                      Loading more…
                    </Text>
                  </Center>
                ) : (
                  // 1px sentinel — when it scrolls into view the effect reveals more.
                  <div ref={sentinelRef} aria-hidden style={{ height: 1 }} />
                )
              ) : (
                <Button
                  variant="subtle"
                  onClick={onReachEnd}
                  loading={isFetchingMore}
                >
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
