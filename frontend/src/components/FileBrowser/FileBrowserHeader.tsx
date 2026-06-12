import { Button, Center, Group, SegmentedControl, Text, TextInput, Tooltip } from "@mantine/core";
import { ChevronDown, FolderUp, LayoutGrid, List as ListIcon, Search, Share2, Trash2, Upload } from "lucide-react";
import { useState } from "react";
import { FileBreadcrumbs } from "./FileBreadcrumbs";
import { TtlPopover } from "@/components/TtlPopover/TtlPopover";
import type { DisplayMode } from "@/hooks/useDisplayMode";

interface FileBrowserHeaderProps {
  bucket: string;
  roleId: string;
  path: string;
  searchQuery: string;
  onSearchChange: (q: string) => void;
  mode: DisplayMode;
  onModeChange: (m: DisplayMode) => void;
  selectedCount: number;
  onBulkDelete: () => void;
  /** Copy URLs for the selection. Optional TTL (seconds) from the popover;
   *  the one-click main button passes none (server default). */
  onBulkCopyUrl: (ttlSeconds?: number) => void;
  onUploadClick: () => void;
  /** Open the folder picker (webkitdirectory input). */
  onUploadFolderClick: () => void;
  /** When true, bulk Delete is rendered disabled with a config-aware tooltip. */
  disableDeletion?: boolean;
  /** Total object count (files + folders) currently loaded for this prefix. */
  objectCount: number;
  /** S3 has more objects beyond the loaded set — show "N+" and continuation controls. */
  truncated: boolean;
  /** Server continuation fetch in flight (loadMore/loadAll). */
  isLoadingMore: boolean;
  /** Fetch the next chunk of objects from the server. */
  onLoadMore: () => void;
  /** Drain all remaining chunks from the server. */
  onLoadAll: () => void;
  /** Server default presigned TTL (seconds). */
  defaultTtl?: number;
  /** Configured max presigned TTL (seconds). */
  maxTtl?: number;
}

export function FileBrowserHeader({
  bucket,
  roleId,
  path,
  searchQuery,
  onSearchChange,
  mode,
  onModeChange,
  selectedCount,
  onBulkDelete,
  onBulkCopyUrl,
  onUploadClick,
  onUploadFolderClick,
  disableDeletion = false,
  objectCount,
  truncated,
  isLoadingMore,
  onLoadMore,
  onLoadAll,
  defaultTtl = 3600,
  maxTtl = 604800,
}: FileBrowserHeaderProps) {
  const [bulkTtlOpen, setBulkTtlOpen] = useState(false);

  return (
    <Group justify="space-between" mb="md" wrap="wrap" gap="sm">
      <FileBreadcrumbs bucket={bucket} roleId={roleId} path={path} />
      <Group gap="sm">
        <TextInput
          placeholder="Filter files…"
          value={searchQuery}
          onChange={(e) => onSearchChange(e.currentTarget.value)}
          leftSection={<Search size={14} />}
          size="sm"
          style={{ minWidth: 200 }}
        />
        <Group gap="xs" align="center" wrap="nowrap">
          <Text size="sm" c="dimmed">
            {truncated
              ? `${objectCount}+ objects`
              : `${objectCount} object${objectCount === 1 ? "" : "s"}`}
          </Text>
          {truncated && (
            <>
              <Button
                size="xs"
                variant="light"
                onClick={onLoadMore}
                loading={isLoadingMore}
                // Mantine's `loading` shows a spinner but does NOT block clicks
                // — without `disabled`, a double-click fires two concurrent
                // fetchNextPage calls and appends duplicate pages (same
                // double-submit guard as the Settings Save bar, PR #24/#37).
                disabled={isLoadingMore}
              >
                Load more
              </Button>
              <Button
                size="xs"
                variant="subtle"
                onClick={onLoadAll}
                loading={isLoadingMore}
                disabled={isLoadingMore}
              >
                Load all
              </Button>
            </>
          )}
        </Group>
        <SegmentedControl
          value={mode}
          onChange={(v) => onModeChange(v as DisplayMode)}
          data={[
            {
              value: "table",
              label: (
                <Center>
                  <ListIcon size={14} aria-label="Table view" />
                </Center>
              ),
            },
            {
              value: "grid",
              label: (
                <Center>
                  <LayoutGrid size={14} aria-label="Grid view" />
                </Center>
              ),
            },
          ]}
          size="sm"
        />
        {selectedCount > 0 && (
          <>
            <Button.Group>
              <Tooltip
                label="Copy shareable links (expire after the configured default; no login required)"
                withArrow
                multiline
                w={260}
              >
                <Button
                  variant="light"
                  leftSection={<Share2 size={14} />}
                  onClick={() => onBulkCopyUrl()}
                  size="sm"
                >
                  Copy URLs ({selectedCount})
                </Button>
              </Tooltip>
              <TtlPopover
                opened={bulkTtlOpen}
                onClose={() => setBulkTtlOpen(false)}
                defaultTtl={defaultTtl}
                maxTtl={maxTtl}
                onConfirm={(ttl) => onBulkCopyUrl(ttl)}
                target={
                  <Button
                    variant="light"
                    size="sm"
                    px={6}
                    onClick={() => setBulkTtlOpen((o) => !o)}
                    aria-label="Choose link validity"
                  >
                    <ChevronDown size={14} />
                  </Button>
                }
              />
            </Button.Group>
            <Tooltip
              label="Deletion is disabled in the server config."
              withArrow
              disabled={!disableDeletion}
            >
              <Button
                color="red"
                variant="light"
                leftSection={<Trash2 size={14} />}
                onClick={onBulkDelete}
                size="sm"
                disabled={disableDeletion}
              >
                Delete ({selectedCount})
              </Button>
            </Tooltip>
          </>
        )}
        <Button
          leftSection={<FolderUp size={14} />}
          onClick={onUploadFolderClick}
          size="sm"
          variant="default"
        >
          Upload folder
        </Button>
        <Button leftSection={<Upload size={14} />} onClick={onUploadClick} size="sm">
          Upload
        </Button>
      </Group>
    </Group>
  );
}
