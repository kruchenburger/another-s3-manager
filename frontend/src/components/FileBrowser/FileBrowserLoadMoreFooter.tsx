import { Button, Center } from "@mantine/core";
import { ChevronDown } from "lucide-react";

interface FileBrowserLoadMoreFooterProps {
  /** Server continuation fetch in flight — drives the spinner and the `disabled` re-click guard below. */
  loading: boolean;
  onLoadMore: () => void;
}

/**
 * Bottom-of-list "Load more" affordance. Rendered inside the scroll container
 * AFTER the virtualized list so the user can fetch the next chunk without
 * scrolling back up to the header buttons.
 *
 * Shown only when lazy-loading is OFF (with lazy on, the near-end sentinel
 * auto-loads the next chunk on scroll, so a manual bottom button never gets a
 * chance to be useful) and more objects remain on the server. "Load all" stays
 * header-only — at the bottom you've just scrolled the loaded chunk, so the
 * natural next step is one more chunk, not draining everything.
 */
export function FileBrowserLoadMoreFooter({
  loading,
  onLoadMore,
}: FileBrowserLoadMoreFooterProps) {
  return (
    <Center py="md">
      <Button
        variant="light"
        size="sm"
        leftSection={<ChevronDown size={16} />}
        loading={loading}
        // Mantine's `loading` shows a spinner but does NOT block clicks — without
        // `disabled`, a double-click fires two concurrent fetchNextPage calls and
        // appends duplicate pages (same guard as the header Load more, PR #24/#37).
        disabled={loading}
        onClick={onLoadMore}
      >
        Load more
      </Button>
    </Center>
  );
}
