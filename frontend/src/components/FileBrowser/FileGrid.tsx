import { useEffect } from "react";
import { Button, Center, SimpleGrid, Stack } from "@mantine/core";
import { useInView } from "react-intersection-observer";
import type { FileEntry } from "@/types/api";
import { FileCard } from "./FileCard";

interface FileGridProps {
  files: FileEntry[];
  selected: Set<string>;
  onToggleSelect: (name: string, shiftKey: boolean) => void;
  onNavigate: (name: string) => void;
  onDownload: (name: string) => void;
  onCopyUrl: (name: string) => void;
  onPreview: (name: string) => void;
  onDelete: (name: string) => void;
  // Forwarded to FileCard so each card can fetch its own presigned thumbnail URL.
  bucket: string;
  roleId: string;
  path: string;
  hasMoreInMemory: boolean;
  onRevealMore: () => void;
  lazyLoadingEnabled: boolean;
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
  hasMoreInMemory,
  onRevealMore,
  lazyLoadingEnabled,
}: FileGridProps) {
  // Sentinel that reveals the next in-memory slice when scrolled into view,
  // mounted only when lazy loading is enabled. rootMargin=100px so the next
  // cards appear before the user actually hits the bottom.
  const { ref: sentinelRef, inView } = useInView({ rootMargin: "100px" });

  // In-memory slice growth — instant, no network, no loader (cards already in
  // memory). Auto-reveal on scroll when lazy loading is on, else a Show more button.
  useEffect(() => {
    if (lazyLoadingEnabled && hasMoreInMemory && inView) {
      onRevealMore();
    }
  }, [lazyLoadingEnabled, hasMoreInMemory, inView, onRevealMore]);

  return (
    <Stack gap="md">
      <SimpleGrid cols={{ base: 2, sm: 3, md: 4, lg: 6 }} spacing="md">
        {files.map((file, i) => (
          <FileCard
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
            bucket={bucket}
            roleId={roleId}
            path={path}
          />
        ))}
      </SimpleGrid>
      {hasMoreInMemory && (
        <Center>
          {lazyLoadingEnabled ? (
            <div
              ref={sentinelRef}
              aria-hidden
              style={{ height: 1, width: "100%" }}
            />
          ) : (
            <Button variant="subtle" onClick={onRevealMore}>
              Show more
            </Button>
          )}
        </Center>
      )}
    </Stack>
  );
}
