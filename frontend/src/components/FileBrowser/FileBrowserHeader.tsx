import { Center, Group, SegmentedControl, TextInput } from "@mantine/core";
import { LayoutGrid, List as ListIcon, Search } from "lucide-react";
import { UploadSplitButton } from "./UploadSplitButton";
import { LoadSplitButton } from "./LoadSplitButton";
import type { DisplayMode } from "@/hooks/useDisplayMode";

interface FileBrowserHeaderProps {
  searchQuery: string;
  onSearchChange: (q: string) => void;
  mode: DisplayMode;
  onModeChange: (m: DisplayMode) => void;
  onUploadClick: () => void;
  /** Open the folder picker (webkitdirectory input). */
  onUploadFolderClick: () => void;
  /** S3 has more objects beyond the loaded set — show continuation controls.
   * The object count itself lives in BucketPageHeader now. */
  truncated: boolean;
  /** Server continuation fetch in flight (loadMore/loadAll). */
  isLoadingMore: boolean;
  /** Fetch the next chunk of objects from the server. */
  onLoadMore: () => void;
  /** Drain all remaining chunks from the server. */
  onLoadAll: () => void;
}

export function FileBrowserHeader({
  searchQuery,
  onSearchChange,
  mode,
  onModeChange,
  onUploadClick,
  onUploadFolderClick,
  truncated,
  isLoadingMore,
  onLoadMore,
  onLoadAll,
}: FileBrowserHeaderProps) {
  return (
    <Group justify="flex-end" mb="md" wrap="wrap" gap="sm">
      <Group gap="sm">
        <TextInput
          placeholder="Filter files…"
          value={searchQuery}
          onChange={(e) => onSearchChange(e.currentTarget.value)}
          leftSection={<Search size={14} />}
          size="sm"
          style={{ minWidth: 200 }}
        />
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
        {truncated && (
          <LoadSplitButton
            onLoadMore={onLoadMore}
            onLoadAll={onLoadAll}
            loading={isLoadingMore}
          />
        )}
        {/* View toggle sits with the filter; the two split buttons (Load
            continuation + Upload) are grouped together at the end so a control
            never sits sandwiched between them. Bulk Copy URLs + Delete live in
            the contextual BulkActionBar (rendered by FileBrowser). */}
        <UploadSplitButton
          onUploadFiles={onUploadClick}
          onUploadFolder={onUploadFolderClick}
        />
      </Group>
    </Group>
  );
}
