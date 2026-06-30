import { type RefObject } from "react";
import { Box } from "@mantine/core";
import { useElementSize } from "@mantine/hooks";
import { useVirtualizer } from "@tanstack/react-virtual";
import type { FileEntry } from "@/types/api";
import { FileCard } from "./FileCard";
import { useNearEndAutoLoad } from "./useNearEndAutoLoad";

interface FileGridProps {
  files: FileEntry[];
  selected: Set<string>;
  onToggleSelect: (name: string, shiftKey: boolean) => void;
  onNavigate: (name: string) => void;
  onDownload: (name: string) => void;
  onCopyUrl: (name: string) => void;
  onCopyUrlWithTtl?: (name: string, ttlSeconds: number) => void;
  onPreview: (name: string) => void;
  onDelete: (name: string) => void;
  bucket: string;
  roleId: string;
  path: string;
  /** Server default presigned TTL (seconds) — forwarded to FileCard → FileActions. */
  defaultTtl?: number;
  /** Configured max presigned TTL (seconds) — forwarded to FileCard → FileActions. */
  maxTtl?: number;
  scrollRef: RefObject<HTMLDivElement | null>;
  autoLoadEnabled: boolean;
  onLoadMore: () => void;
}

// Card-row height (px) = the MEASURED rendered height of one FileCard:
// Mantine Card padding md (16×2) + checkbox/actions row + mb sm + 120px media
// area + mb sm + single-line label + single-line size ≈ 241px. The virtualizer
// spaces rows `ROW_HEIGHT + GAP` apart, so this MUST be ≥ the real card height
// or rows overlap — cards stack onto the row below (was 200, which is ~41px too
// short, so every row visibly overlapped the next). Re-measure if FileCard's
// content changes.
const ROW_HEIGHT = 241;
const GAP = 16; // Mantine "md"

// Column count by container width — mirrors the old SimpleGrid breakpoints
// cols={{ base: 2, sm: 3, md: 4, lg: 6 }} using Mantine's px breakpoints.
function columnsForWidth(width: number): number {
  if (width >= 1200) return 6; // lg
  if (width >= 992) return 4; // md
  if (width >= 768) return 3; // sm
  return 2; // base
}

export function FileGrid({
  files,
  selected,
  onToggleSelect,
  onNavigate,
  onDownload,
  onCopyUrl,
  onCopyUrlWithTtl,
  onPreview,
  onDelete,
  bucket,
  roleId,
  path,
  defaultTtl,
  maxTtl,
  scrollRef,
  autoLoadEnabled,
  onLoadMore,
}: FileGridProps) {
  const { ref: sizeRef, width } = useElementSize();
  const columns = columnsForWidth(width || 1200);
  const rowCount = Math.ceil(files.length / columns);

  const virtualizer = useVirtualizer({
    count: rowCount,
    getScrollElement: () => scrollRef.current,
    estimateSize: () => ROW_HEIGHT + GAP,
    overscan: 4,
  });

  useNearEndAutoLoad(virtualizer, rowCount, autoLoadEnabled, onLoadMore);

  return (
    <Box ref={sizeRef}>
      <Box style={{ position: "relative", height: virtualizer.getTotalSize() }}>
        {virtualizer.getVirtualItems().map((vrow) => {
          const start = vrow.index * columns;
          const rowItems = files.slice(start, start + columns);
          return (
            <Box
              key={vrow.key}
              style={{
                position: "absolute",
                top: 0,
                left: 0,
                width: "100%",
                transform: `translateY(${vrow.start}px)`,
                display: "grid",
                gridTemplateColumns: `repeat(${columns}, 1fr)`,
                gap: GAP,
              }}
            >
              {rowItems.map((file, k) => (
                <FileCard
                  key={file.name}
                  file={file}
                  index={start + k}
                  selected={selected.has(file.name)}
                  onToggleSelect={onToggleSelect}
                  onNavigate={onNavigate}
                  onDownload={onDownload}
                  onCopyUrl={onCopyUrl}
                  onCopyUrlWithTtl={onCopyUrlWithTtl}
                  onPreview={onPreview}
                  onDelete={onDelete}
                  bucket={bucket}
                  roleId={roleId}
                  path={path}
                  defaultTtl={defaultTtl}
                  maxTtl={maxTtl}
                />
              ))}
            </Box>
          );
        })}
      </Box>
    </Box>
  );
}
