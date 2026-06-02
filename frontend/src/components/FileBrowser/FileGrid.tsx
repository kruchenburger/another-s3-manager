import { useEffect } from "react";
import { Button, Center, Loader, SimpleGrid, Stack, Text } from "@mantine/core";
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
  hasMore: boolean;
  isFetchingMore: boolean;
  onReachEnd: () => void;
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
  hasMore,
  isFetchingMore,
  onReachEnd,
  lazyLoadingEnabled,
}: FileGridProps) {
  // Sentinel that drives the next reveal/fetch when scrolled into view,
  // mounted only when lazy loading is enabled. rootMargin=100px so the next
  // cards appear before the user actually hits the bottom.
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
      {hasMore && (
        <Center>
          {lazyLoadingEnabled ? (
            isFetchingMore ? (
              <>
                <Loader size="sm" />
                <Text size="sm" c="dimmed" ml="xs">
                  Loading more…
                </Text>
              </>
            ) : (
              <div
                ref={sentinelRef}
                aria-hidden
                style={{ height: 1, width: "100%" }}
              />
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
        </Center>
      )}
    </Stack>
  );
}
