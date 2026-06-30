import { Center, Group, SegmentedControl, Text, TextInput } from "@mantine/core";
import { LayoutGrid, List as ListIcon, Search } from "lucide-react";
import { FileBreadcrumbs } from "./FileBreadcrumbs";
import { UploadSplitButton } from "./UploadSplitButton";
import { LoadSplitButton } from "./LoadSplitButton";
import type { DisplayMode } from "@/hooks/useDisplayMode";

interface FileBrowserHeaderProps {
  bucket: string;
  roleId: string;
  path: string;
  searchQuery: string;
  onSearchChange: (q: string) => void;
  mode: DisplayMode;
  onModeChange: (m: DisplayMode) => void;
  onUploadClick: () => void;
  /** Open the folder picker (webkitdirectory input). */
  onUploadFolderClick: () => void;
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
}

export function FileBrowserHeader({
  bucket,
  roleId,
  path,
  searchQuery,
  onSearchChange,
  mode,
  onModeChange,
  onUploadClick,
  onUploadFolderClick,
  objectCount,
  truncated,
  isLoadingMore,
  onLoadMore,
  onLoadAll,
}: FileBrowserHeaderProps) {
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
            <LoadSplitButton
              onLoadMore={onLoadMore}
              onLoadAll={onLoadAll}
              loading={isLoadingMore}
            />
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
        {/* Bulk Copy URLs + Delete live in the contextual BulkActionBar (rendered
            by FileBrowser); upload + load-continuation are consolidated into the
            two split buttons below. */}
        <UploadSplitButton
          onUploadFiles={onUploadClick}
          onUploadFolder={onUploadFolderClick}
        />
      </Group>
    </Group>
  );
}
