import {
  Affix,
  Box,
  Button,
  CloseButton,
  Group,
  Paper,
  Text,
  Tooltip,
  Transition,
} from "@mantine/core";
import { ChevronDown, Share2, Trash2 } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { TtlPopover } from "@/components/TtlPopover/TtlPopover";
import classes from "./BulkActionBar.module.css";

interface BulkActionBarProps {
  /** Number of selected items (= selected.size). The bar shows when > 0. */
  count: number;
  /** Clear the selection (= `clear` from useShiftSelect). Wired to ✕ and Esc. */
  onClear: () => void;
  /** Copy presigned URLs for the selection; optional TTL from the popover. */
  onCopyUrls: (ttlSeconds?: number) => void;
  /** Delete the selection (opens ConfirmDeleteModal). */
  onDelete: () => void;
  /** When true, Delete renders disabled with a config-aware tooltip. */
  disableDeletion?: boolean;
  /** Server default presigned TTL (seconds). */
  defaultTtl?: number;
  /** Configured max presigned TTL (seconds). */
  maxTtl?: number;
  /** True while a bulk copy is in flight — disables Copy URLs to block double-submit. */
  busy?: boolean;
}

/**
 * Contextual bulk-action surface for the file browser. Replaces the inline
 * Copy-URLs + Delete buttons that used to be injected into FileBrowserHeader on
 * selection (which reflowed the toolbar). It fades in only when something is
 * selected, so the at-rest toolbar never changes shape.
 *
 * Mounted as a sibling of the virtualized scroll container (FileBrowser renders
 * it next to the modals): Mantine `Affix` portals to the body, so it is never
 * inside `scrollArea` and never affected by virtualization. A bottom-CENTER pill
 * (positioned in BulkActionBar.module.css) so it never overlaps the
 * `ScrollToTopButton` Affix at `bottom:20 right:36`. The `data-bulk-bar` marker
 * drives the global.css `:has()` rule that lifts bottom toasts clear of the bar.
 */
export function BulkActionBar({
  count,
  onClear,
  onCopyUrls,
  onDelete,
  disableDeletion = false,
  defaultTtl = 3600,
  maxTtl = 604800,
  busy = false,
}: BulkActionBarProps) {
  const open = count > 0;
  const [ttlOpen, setTtlOpen] = useState(false);
  const firstActionRef = useRef<HTMLButtonElement>(null);
  const prevOpen = useRef(false);

  // Esc clears the selection — but if the TTL popover is open, the first Esc
  // closes that instead (so the user doesn't lose their selection while just
  // dismissing a menu). Scoped to while the bar is shown.
  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key !== "Escape") return;
      if (ttlOpen) {
        setTtlOpen(false);
        return;
      }
      onClear();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [open, ttlOpen, onClear]);

  // Move focus to the first action when the selection FIRST appears (0 → 1+),
  // so keyboard users land on the bar instead of hunting for it. Only on the
  // rising edge — re-focusing on every count change would steal focus mid-task.
  useEffect(() => {
    if (open && !prevOpen.current) firstActionRef.current?.focus();
    prevOpen.current = open;
  }, [open]);

  return (
    <Affix position={{ bottom: 16 }} zIndex={120} className={classes.affix}>
      <Transition
        mounted={open}
        transition="slide-up"
        duration={200}
        timingFunction="ease"
      >
        {(style) => (
          <Paper
            style={style}
            className={classes.bar}
            role="region"
            aria-label="Bulk actions for selected files"
            radius="lg"
            shadow="md"
            withBorder
            p={6}
            data-bulk-bar
          >
            <Group gap="xs" wrap="nowrap">
              <CloseButton aria-label="Clear selection" onClick={onClear} />
              {/* nowrap: on narrow screens "7 selected" wrapped into two
                  lines and stretched the pill vertically (smoke feedback). */}
              <Text size="sm" fw={600} pr={4} style={{ whiteSpace: "nowrap" }}>
                {count} selected
              </Text>
              <Button.Group>
                <Tooltip
                  label="Copy shareable links (expire after the configured default; no login required)"
                  withArrow
                  multiline
                  w={260}
                >
                  <Button
                    ref={firstActionRef}
                    variant="light"
                    size="sm"
                    leftSection={<Share2 size={14} />}
                    onClick={() => onCopyUrls()}
                    loading={busy}
                    disabled={busy}
                    // aria-label keeps the accessible name when the visible
                    // text label is hidden on phones (width budget).
                    aria-label="Copy URLs"
                  >
                    <Box component="span" visibleFrom="sm">
                      Copy URLs
                    </Box>
                  </Button>
                </Tooltip>
                <TtlPopover
                  opened={ttlOpen}
                  onClose={() => setTtlOpen(false)}
                  defaultTtl={defaultTtl}
                  maxTtl={maxTtl}
                  onConfirm={(ttl) => onCopyUrls(ttl)}
                  target={
                    <Button
                      variant="light"
                      size="sm"
                      px={6}
                      onClick={() => setTtlOpen((o) => !o)}
                      aria-label="Choose link validity"
                      disabled={busy}
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
                  size="sm"
                  leftSection={<Trash2 size={14} />}
                  onClick={onDelete}
                  disabled={disableDeletion}
                  aria-label="Delete"
                >
                  <Box component="span" visibleFrom="sm">
                    Delete
                  </Box>
                </Button>
              </Tooltip>
            </Group>
          </Paper>
        )}
      </Transition>
    </Affix>
  );
}
