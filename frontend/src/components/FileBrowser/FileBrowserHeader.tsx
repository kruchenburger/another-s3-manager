import {
  ActionIcon,
  Box,
  CloseButton,
  Group,
  TextInput,
  Tooltip,
} from "@mantine/core";
import { LayoutGrid, List as ListIcon, Search } from "lucide-react";
import { useState } from "react";
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
  bucket,
  roleId,
  path,
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
  // Mobile-only: the filter collapses to a search icon so filter + view
  // toggle + Upload share one row on any phone (a fixed-width input didn't
  // fit the narrower Androids). Desktop always shows the input.
  const [mobileSearchOpen, setMobileSearchOpen] = useState(false);

  const searchInput = (width: number | string, isMobileInstance = false) => (
    <TextInput
      placeholder="Filter files…"
      value={searchQuery}
      onChange={(e) => onSearchChange(e.currentTarget.value)}
      leftSection={<Search size={14} />}
      size="sm"
      w={width}
      // Only the tap-to-expand mobile instance autofocuses on mount; the
      // always-mounted desktop instance must never steal focus.
      autoFocus={isMobileInstance}
      rightSection={
        isMobileInstance ? (
          <CloseButton
            size="sm"
            aria-label="Close search"
            onClick={() => {
              onSearchChange("");
              setMobileSearchOpen(false);
            }}
          />
        ) : undefined
      }
    />
  );

  // Breadcrumbs anchor the row's left side — without them the controls-only
  // row read as a dead "runway" under the page-identity line (smoke feedback).
  return (
    <Group justify="space-between" mb="md" wrap="wrap" gap="sm">
      <FileBreadcrumbs bucket={bucket} roleId={roleId} path={path} />
      <Group gap="sm">
        <Box visibleFrom="sm">{searchInput(200)}</Box>
        <Box hiddenFrom="sm">
          {mobileSearchOpen ? (
            searchInput(180, true)
          ) : (
            <ActionIcon
              variant={searchQuery ? "light" : "subtle"}
              color="gray"
              size="lg"
              aria-label="Search files"
              onClick={() => setMobileSearchOpen(true)}
            >
              <Search size={16} />
            </ActionIcon>
          )}
        </Box>
        {/* Airify: the boxed SegmentedControl clashed with the borderless
            toolbar (smoke feedback) — the toggle is now the same subtle
            ActionIcon pair used across the app; the active view gets the
            "light" chip fill. aria-pressed carries the state. */}
        <Group gap={2}>
          <Tooltip label="Table view">
            <ActionIcon
              variant={mode === "table" ? "light" : "subtle"}
              color="gray"
              size="lg"
              aria-label="Table view"
              aria-pressed={mode === "table"}
              onClick={() => onModeChange("table")}
            >
              <ListIcon size={16} />
            </ActionIcon>
          </Tooltip>
          <Tooltip label="Grid view">
            <ActionIcon
              variant={mode === "grid" ? "light" : "subtle"}
              color="gray"
              size="lg"
              aria-label="Grid view"
              aria-pressed={mode === "grid"}
              onClick={() => onModeChange("grid")}
            >
              <LayoutGrid size={16} />
            </ActionIcon>
          </Tooltip>
        </Group>
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
