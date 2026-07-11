import { useState, type CSSProperties } from "react";
import { Anchor, List, Stack, Text } from "@mantine/core";
import { AutoCloseProgress } from "./AutoCloseProgress";
import type { UploadProgressItem } from "./UploadProgress";
import classes from "./UploadSummary.module.css";

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
  // Mantine's notification message body has `overflow: hidden` and `text-overflow: ellipsis`
  // baked into the .m_3d733a3a class, which clips our scrollable list at the
  // toast edge — last row gets cut, headline disappears as the viewport shifts.
  // Override to `visible` here so the entire message area (headline + scroll
  // window + timer bar) renders without Mantine truncation. `position: relative`
  // anchors the absolutely-positioned timer bar to this Stack. These three
  // properties have no Mantine prop equivalents, so an inline style is the
  // only way to express them. Padding-bottom for the timer bar IS a Mantine
  // prop (`pb`) and goes through the `Stack` API instead.
  const wrapperStyle: CSSProperties = {
    position: "relative",
    overflow: "visible",
    textOverflow: "clip",
  };
  const wrapperPb = timer ? 6 : 0;

  if (failed.length === 0 && cancelled === 0) {
    return (
      <Stack gap={0} pb={wrapperPb} style={wrapperStyle}>
        <Text size="sm" fw={500}>
          Uploaded {total} {total === 1 ? "file" : "files"}
        </Text>
        {timer}
      </Stack>
    );
  }

  if (failed.length === 0 && cancelled > 0) {
    return (
      <Stack gap={0} pb={wrapperPb} style={wrapperStyle}>
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
    <Stack gap={6} pb={wrapperPb} style={wrapperStyle}>
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
          {failed.length > 3 && (
            // Heading on big lists makes the toast self-describing once the
            // list scrolls past the headline. Kept off small lists since the
            // headline is right above and the heading would be redundant.
            <Text size="xs" c="dimmed" fw={500}>
              Failed files:
            </Text>
          )}
          <div
            // Cap the list at ~5-6 rows; longer lists scroll inside the toast
            // instead of stretching it off-screen. Mantine pauses the
            // notification's autoClose timer on mouseEnter — so while the
            // user reads / scrolls the failed list, the toast won't dismiss
            // out from under them. CSS module also slims the browser
            // scrollbar so it doesn't dominate the panel.
            className={classes.scrollArea}
          >
            <List size="xs" spacing={6} withPadding>
              {failed.map((item) => (
                <List.Item key={item.name}>
                  {/* Filename and error on separate lines — the error (which
                      limit was hit) is the useful part and must never be
                      pushed off by a long wrapping filename again (this alone
                      fixes the reported bug, regardless of the filename's own
                      overflow behavior). The filename ellipsizes to a single
                      line via `truncate`; title carries the full name on
                      hover, and the full name stays in the DOM text for
                      screen readers. */}
                  <Stack gap={2}>
                    <Text size="xs" fw={500} truncate title={item.name} className={classes.filename}>
                      {item.name}
                    </Text>
                    {item.error && (
                      <Text size="xs" c="dimmed">
                        {item.error}
                      </Text>
                    )}
                  </Stack>
                </List.Item>
              ))}
            </List>
          </div>
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
