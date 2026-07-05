import { Center, Loader, Stack, Text } from "@mantine/core";
import { useEffect, useState } from "react";

interface DelayedLoaderProps {
  /**
   * Delay in ms before the loader actually appears. Fetches that complete
   * faster than this never flash a spinner — avoiding the "flicker → blank
   * → content" sequence on warm-cache navigation. 500ms is the platform-
   * common threshold: long enough that users see "instant" on fast paths,
   * short enough that anything slower than a single S3 round trip gets the
   * feedback. Defaults are fine; raise for explicitly-slow operations.
   */
  delayMs?: number;
  /** Mantine Loader size — sm/md/lg or px. */
  size?: number | string;
  /**
   * Optional label rendered under the spinner — keeps long-running waits
   * from feeling empty. Matches the vanilla UI's "Loading files…" copy.
   * Omit when the surrounding screen already explains what's loading
   * (auth gate, modal preview).
   */
  label?: string;
}

/**
 * Shared loading state used everywhere a TanStack Query is in flight.
 *
 *   - Anchored at `mih: 60vh` so the spinner sits at the same place across
 *     every page (file browser, admin pages, role page) instead of
 *     jumping with the surrounding content height.
 *   - Delayed by default so a sub-500ms fetch never flashes a spinner.
 *
 * Earlier rounds used a branded CubeLogo here; under heavy file-table
 * render the SVG-filter glow stalled and Firefox flagged the page as
 * "slowing down". A plain Mantine spinner is boring but reliable —
 * branding lives on the login / error / 404 / auth-guard screens where
 * there's no render pressure.
 */
export function DelayedLoader({
  delayMs = 500,
  size = "lg",
  label,
}: DelayedLoaderProps) {
  const [show, setShow] = useState(delayMs === 0);
  useEffect(() => {
    if (delayMs === 0) return;
    const id = window.setTimeout(() => setShow(true), delayMs);
    return () => window.clearTimeout(id);
  }, [delayMs]);

  return (
    <Center mih="60vh" aria-busy="true" aria-live="polite">
      {show ? (
        <Stack align="center" gap="sm">
          <Loader size={size} />
          {label && (
            <Text size="sm" c="dimmed">
              {label}
            </Text>
          )}
        </Stack>
      ) : null}
    </Center>
  );
}
