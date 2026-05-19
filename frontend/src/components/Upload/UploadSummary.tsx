import { useState } from "react";
import { Anchor, List, Stack, Text } from "@mantine/core";
import { AutoCloseProgress } from "./AutoCloseProgress";
import type { UploadProgressItem } from "./UploadProgress";

interface UploadSummaryProps {
  items: UploadProgressItem[];
  /** When the parent toast has an autoClose timer, pass the duration here so
   *  the summary can render a thin animated bar that empties at the same rate
   *  the toast will dismiss. Omit (or set to 0) to hide the indicator. */
  autoCloseMs?: number;
}

/**
 * Final-state summary rendered inside the upload toast once all per-file
 * uploads have settled (done / error / cancelled).
 *
 * For a fully-successful batch this is a single line. For a partially-failed
 * batch it surfaces the failed filenames + their error messages so the user
 * sees WHICH file failed — without this, a 223/224 batch leaves the user with
 * no way to know which file was the bad one. When > 3 files failed, the list
 * is collapsed behind a "Show N failed files" toggle so the toast doesn't
 * blow up into a wall of text; ≤ 3 renders inline (clearer than hiding).
 *
 * For a pure-cancellation batch (user clicked the cancel button, nothing
 * actually broke), the copy says "Upload cancelled" so the user understands
 * this was their action, not a backend failure.
 *
 * We use plain conditional rendering with useState rather than Mantine's
 * Spoiler — Spoiler measures real DOM heights via ResizeObserver, which
 * doesn't work in jsdom, breaking the component tests.
 */
export function UploadSummary({ items, autoCloseMs }: UploadSummaryProps) {
  const total = items.length;
  const done = items.filter((i) => i.status === "done").length;
  const failed = items.filter((i) => i.status === "error");
  const cancelled = items.filter((i) => i.status === "cancelled").length;
  // Default: show inline when ≤ 3, hide when > 3 (toast would otherwise
  // become a wall of text on a large batch with many failures).
  const [expanded, setExpanded] = useState(failed.length <= 3);

  // Reusable trailing indicator. Rendered after the body of every branch so
  // the user gets a consistent "this toast will dismiss" hint. AutoCloseProgress
  // is absolutely positioned along the bottom edge — the wrapping Stack
  // therefore needs `position: relative` so the indicator stays inside its
  // containing block instead of bubbling up to the nearest positioned ancestor
  // (Mantine's notification root, which would visually look fine but is brittle).
  const timer = autoCloseMs && autoCloseMs > 0 ? <AutoCloseProgress durationMs={autoCloseMs} /> : null;
  const wrapperStyle = timer ? { position: "relative" as const, paddingBottom: 6 } : undefined;

  if (failed.length === 0 && cancelled === 0) {
    return (
      <Stack gap={0} style={wrapperStyle}>
        <Text size="sm" fw={500}>
          Uploaded {total} {total === 1 ? "file" : "files"}
        </Text>
        {timer}
      </Stack>
    );
  }

  if (failed.length === 0 && cancelled > 0) {
    return (
      <Stack gap={0} style={wrapperStyle}>
        <Text size="sm" fw={500}>
          Upload cancelled — {done} of {total} files uploaded
        </Text>
        {timer}
      </Stack>
    );
  }

  const headline =
    cancelled > 0
      ? `${done}/${total} files uploaded — ${failed.length} failed, ${cancelled} cancelled`
      : `${done}/${total} files uploaded — ${failed.length} failed`;

  return (
    <Stack gap={6} style={wrapperStyle}>
      <Text size="sm" fw={500}>
        {headline}
      </Text>
      {!expanded && (
        <Anchor
          component="button"
          type="button"
          size="xs"
          onClick={() => setExpanded(true)}
        >
          Show {failed.length} failed file{failed.length === 1 ? "" : "s"}
        </Anchor>
      )}
      {expanded && (
        <>
          <List size="xs" spacing={2} withPadding>
            {failed.map((item) => (
              <List.Item key={item.name}>
                <Text size="xs" component="span" fw={500}>
                  {item.name}
                </Text>
                {item.error && (
                  <Text size="xs" component="span" c="dimmed">
                    {" — "}
                    {item.error}
                  </Text>
                )}
              </List.Item>
            ))}
          </List>
          {failed.length > 3 && (
            <Anchor
              component="button"
              type="button"
              size="xs"
              onClick={() => setExpanded(false)}
            >
              Hide
            </Anchor>
          )}
        </>
      )}
      {timer}
    </Stack>
  );
}
