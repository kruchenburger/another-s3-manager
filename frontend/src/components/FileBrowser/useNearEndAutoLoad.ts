import { useEffect, useRef } from "react";
import type { Virtualizer } from "@tanstack/react-virtual";

// How close to the end (in rows) counts as "reached the end". 1 = only the very
// last row. The virtualizer's own overscan already renders ahead, so a small
// threshold preloads the next server chunk roughly a screenful early — the
// equivalent of the old sentinel's 800px bottom rootMargin.
const END_THRESHOLD = 2;

/**
 * Fire `onLoadMore` once each time the virtualizer's rendered window first
 * reaches within END_THRESHOLD rows of the end while `enabled`.
 *
 * `enabled` is expected to already fold in (lazy && truncated &&
 * !isFetchingNextPage && !searching) so the hook stays dumb. A `firedRef`
 * guards against repeat calls while the window sits at the end (it only re-arms
 * once the window moves back off the end, e.g. after a chunk appends).
 */
export function useNearEndAutoLoad(
  virtualizer: Virtualizer<HTMLDivElement, Element>,
  rowCount: number,
  enabled: boolean,
  onLoadMore: () => void,
) {
  const items = virtualizer.getVirtualItems();
  const lastIndex = items.length ? items[items.length - 1].index : -1;
  const atEnd = rowCount > 0 && lastIndex >= rowCount - END_THRESHOLD;
  const firedRef = useRef(false);

  useEffect(() => {
    if (!enabled || !atEnd) {
      // Re-arm once we move off the end (or get disabled).
      firedRef.current = false;
      return;
    }
    if (firedRef.current) return;
    firedRef.current = true;
    onLoadMore();
  }, [enabled, atEnd, onLoadMore]);
}
