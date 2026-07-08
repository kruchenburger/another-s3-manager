import { Box, Button, Group, Loader, Menu } from "@mantine/core";
import { ChevronDown, Files, ListPlus, Square } from "lucide-react";

interface LoadSplitButtonProps {
  /** Fetch the next chunk of objects from the server. */
  onLoadMore: () => void;
  /** Drain all remaining chunks from the server. */
  onLoadAll: () => void;
  /** Server continuation fetch in flight — spinner + double-submit guard. */
  loading: boolean;
  /** A "Load all" drain is running (many chunks) — show a Stop button instead. */
  loadingAll?: boolean;
  /** Halt an in-progress "Load all". */
  onStopLoadAll?: () => void;
}

/**
 * Consolidated server-continuation control, shown when the listing is truncated.
 * Primary "Load more" (next chunk) with a chevron menu for "Load all" (drain
 * everything). Mirrors UploadSplitButton; replaces the two separate Load more /
 * Load all buttons in FileBrowserHeader.
 *
 * While a "Load all" drain runs (potentially thousands of chunks on a huge
 * level) the whole control collapses to a single "Stop" button — draining
 * 800k objects 300-at-a-time is long, so the user must be able to halt it.
 *
 * `loading` drives both the spinner and the `disabled` re-click guard: Mantine's
 * `loading` shows a spinner but does NOT block clicks, so without `disabled` a
 * double-click fires two concurrent fetchNextPage calls and appends duplicate
 * pages. The chevron is disabled while loading too — opening "Load all"
 * mid-fetch is pointless.
 */
export function LoadSplitButton({
  onLoadMore,
  onLoadAll,
  loading,
  loadingAll = false,
  onStopLoadAll,
}: LoadSplitButtonProps) {
  if (loadingAll) {
    // A spinner makes the ongoing drain obvious (the plain Stop button alone
    // read as idle); the object count is already shown in the page header.
    return (
      <Group gap="xs" wrap="nowrap">
        <Loader size="xs" color="gray" />
        <Button
          variant="light"
          color="red"
          size="sm"
          onClick={onStopLoadAll}
          leftSection={<Square size={14} fill="currentColor" />}
          aria-label="Stop loading"
        >
          Stop
        </Button>
      </Group>
    );
  }

  return (
    <Button.Group>
      {/* Phones: the text swaps for a ListPlus icon (desktop stays text-only
          per the #53 design iteration) so the toolbar row fits 360px. */}
      <Button
        variant="default"
        size="sm"
        onClick={onLoadMore}
        loading={loading}
        disabled={loading}
        aria-label="Load more"
      >
        <Box component="span" visibleFrom="sm">
          Load more
        </Box>
        <Box component="span" hiddenFrom="sm" display="inline-flex">
          <ListPlus size={16} />
        </Box>
      </Button>
      {/* Dropdown width tracks the split-button group (~136px) + a touch, so it
          reads as an extension of the "Load more" button — not a wide Upload-style
          menu. */}
      <Menu position="bottom-end" withinPortal width={144}>
        <Menu.Target>
          <Button
            variant="default"
            size="sm"
            px={8}
            aria-label="More load options"
            disabled={loading}
          >
            <ChevronDown size={14} />
          </Button>
        </Menu.Target>
        <Menu.Dropdown>
          {/* Defense-in-depth: the chevron that opens this menu is already
              disabled while loading, so this item is normally unreachable
              mid-fetch. `disabled={loading}` also covers the sub-frame race after
              clicking "Load all" (before closeOnItemClick unmounts the menu),
              keeping parity with the primary button's double-submit guard. */}
          <Menu.Item
            leftSection={<Files size={14} />}
            onClick={onLoadAll}
            disabled={loading}
          >
            Load all
          </Menu.Item>
        </Menu.Dropdown>
      </Menu>
    </Button.Group>
  );
}
