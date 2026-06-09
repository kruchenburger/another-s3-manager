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
  onPreview: (name: string) => void;
  onDelete: (name: string) => void;
  bucket: string;
  roleId: string;
  path: string;
  scrollRef: RefObject<HTMLDivElement | null>;
  autoLoadEnabled: boolean;
  onLoadMore: () => void;
}

// Fixed card-row height (px): 120px thumbnail box + checkbox/actions row +
// single-line label + size line + Card padding + inter-row gap. Matches the
// Card built in FileCard.tsx (mih=120 media area, lineClamp=1 label).
const ROW_HEIGHT = 200;
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
  onPreview,
  onDelete,
  bucket,
  roleId,
  path,
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
                  onPreview={onPreview}
                  onDelete={onDelete}
                  bucket={bucket}
                  roleId={roleId}
                  path={path}
                />
              ))}
            </Box>
          );
        })}
      </Box>
    </Box>
  );
}
