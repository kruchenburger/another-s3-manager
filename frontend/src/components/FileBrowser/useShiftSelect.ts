import { useCallback, useRef, useState } from "react";

/**
 * Bulk-selection hook with shift-click range support.
 *
 * Tracks the last item the user explicitly toggled ("anchor") and, when a
 * subsequent click happens with Shift held, applies the anchor's new state
 * (selected vs. deselected) to every item in the visible-order range
 * between anchor and target — inclusive.
 *
 * The `orderedNames` argument is the CURRENTLY VISIBLE order (after sort +
 * filter). The range is computed by `indexOf` on that array, so the result
 * matches what the user sees on screen, not the underlying data order.
 *
 * If shift is held but the anchor is missing (first click in the session,
 * or anchor was filtered out), behaviour falls back to a normal toggle.
 */
export function useShiftSelect() {
  const [selected, setSelected] = useState<Set<string>>(new Set());
  // Ref because we read this synchronously inside the next click and never
  // want a re-render solely due to the anchor changing.
  const anchorRef = useRef<string | null>(null);

  const handleToggle = useCallback(
    (name: string, shiftKey: boolean, orderedNames: string[]) => {
      setSelected((prev) => {
        const next = new Set(prev);
        const anchor = anchorRef.current;
        const anchorIdx = anchor ? orderedNames.indexOf(anchor) : -1;
        const targetIdx = orderedNames.indexOf(name);

        if (shiftKey && anchor && anchorIdx !== -1 && targetIdx !== -1) {
          // Range op: the action applied to every item in the range is the
          // opposite of the anchor's CURRENT membership — same intent the
          // user expressed on the anchor click. (Anchor selected → range
          // selects; anchor deselected → range deselects.)
          const [from, to] =
            anchorIdx <= targetIdx
              ? [anchorIdx, targetIdx]
              : [targetIdx, anchorIdx];
          const anchorIsSelected = prev.has(anchor);
          for (let i = from; i <= to; i++) {
            const itemName = orderedNames[i];
            if (anchorIsSelected) next.add(itemName);
            else next.delete(itemName);
          }
          // Don't advance the anchor on a range op — keeps the user's
          // mental model "the anchor is the last single-click I made".
          return next;
        }

        // Plain toggle.
        if (next.has(name)) next.delete(name);
        else next.add(name);
        anchorRef.current = name;
        return next;
      });
    },
    [],
  );

  const toggleAll = useCallback((orderedNames: string[]) => {
    setSelected((prev) => {
      const allSelected =
        orderedNames.length > 0 && orderedNames.every((n) => prev.has(n));
      // Reset anchor when toggling all — there's no meaningful "last clicked"
      // after a bulk op.
      anchorRef.current = null;
      return allSelected ? new Set() : new Set(orderedNames);
    });
  }, []);

  const clear = useCallback(() => {
    anchorRef.current = null;
    setSelected(new Set());
  }, []);

  return { selected, handleToggle, toggleAll, clear };
}
