import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MantineProvider } from "@mantine/core";
import { UploadSummary } from "@/components/Upload/UploadSummary";
import type { UploadProgressItem } from "@/components/Upload/UploadProgress";

describe("UploadSummary", () => {
  it("shows the all-done headline when everything succeeded", () => {
    render(
      <MantineProvider>
        <UploadSummary
          items={[
            { name: "a.txt", status: "done" },
            { name: "b.txt", status: "done" },
          ]}
        />
      </MantineProvider>,
    );
    expect(screen.getByText("Uploaded 2 files")).toBeInTheDocument();
  });

  it("uses singular for one file", () => {
    render(
      <MantineProvider>
        <UploadSummary items={[{ name: "x.txt", status: "done" }]} />
      </MantineProvider>,
    );
    expect(screen.getByText("Uploaded 1 file")).toBeInTheDocument();
  });

  it("shows the failed-count headline and surfaces failed filenames inline when ≤ 3", () => {
    render(
      <MantineProvider>
        <UploadSummary
          items={[
            { name: "a.txt", status: "done" },
            { name: "b.txt", status: "done" },
            { name: "huge.zip", status: "error", error: "File is 419 MB, limit is 100 MB" },
          ]}
        />
      </MantineProvider>,
    );
    expect(screen.getByText(/2\/3 files uploaded — 1 failed/)).toBeInTheDocument();
    // The failed-files spoiler is open by default when failed.length ≤ 3.
    // The filename ellipsizes to one line via Mantine `truncate`; the full
    // name is carried on the `title` attribute (hover tooltip), so we assert
    // via getByTitle.
    expect(screen.getByTitle("huge.zip")).toBeInTheDocument();
    expect(screen.getByText(/419 MB, limit is 100 MB/)).toBeInTheDocument();
  });

  it("keeps the full filename and the full error visible (not clipped) for a long filename", () => {
    const longName =
      "MediaTek-MT7920-MT7921-MT7922-and-MT7925-Wi-Fi-UWD_5153K_WIN64_5.5.0.3236_A12.EXE";
    const fullError = "File is 41.9 MB, limit is 1.0 MB";
    render(
      <MantineProvider>
        <UploadSummary
          items={[{ name: longName, status: "error", error: fullError }]}
        />
      </MantineProvider>,
    );

    // The filename ellipsizes visually via CSS `truncate`, but the DOM text
    // node still holds the FULL name (truncation is overflow-only), so the
    // extension is reachable by both getByTitle (hover tooltip) and screen
    // readers reading textContent.
    const filenameRow = screen.getByTitle(longName);
    expect(filenameRow).toBeInTheDocument();
    expect(filenameRow).toHaveTextContent(longName);

    // The error is never split/truncated — the full string, including the
    // trailing unit ("MB"), must be present in the DOM.
    const errorNode = screen.getByText(fullError);
    expect(errorNode).toBeInTheDocument();

    // Filename and error render as separate elements/lines, not one inline
    // run of text — the error can no longer be pushed off by a wrapping name.
    expect(errorNode).not.toBe(filenameRow);
    expect(filenameRow.contains(errorNode)).toBe(false);
    expect(errorNode.contains(filenameRow)).toBe(false);
  });

  it("collapses the failed list into a Spoiler when > 3 failed", async () => {
    const items: UploadProgressItem[] = [
      ...Array.from({ length: 5 }, (_, i) => ({
        name: `bad-${i}.bin`,
        status: "error" as const,
        error: `boom-${i}`,
      })),
      ...Array.from({ length: 10 }, (_, i) => ({
        name: `ok-${i}.bin`,
        status: "done" as const,
      })),
    ];

    render(
      <MantineProvider>
        <UploadSummary items={items} />
      </MantineProvider>,
    );

    expect(screen.getByText(/10\/15 files uploaded — 5 failed/)).toBeInTheDocument();

    // Spoiler starts collapsed for > 3 failures; the toggle button shows
    // "Show N failed files". The list items might still be in the DOM
    // (Spoiler measures content height) but not visible until expanded.
    const toggle = screen.getByText(/show 5 failed files/i);
    expect(toggle).toBeInTheDocument();
    await userEvent.click(toggle);
    // After expand, the first failed name is now in view. Asserted via
    // `title` (see note above) — the filename ellipsizes via `truncate` and
    // carries its full name on the title attribute.
    expect(screen.getByTitle("bad-0.bin")).toBeInTheDocument();
  });

  it("shows a 'cancelled' headline when the user aborted the batch with no errors", () => {
    render(
      <MantineProvider>
        <UploadSummary
          items={[
            { name: "a.txt", status: "done" },
            { name: "b.txt", status: "done" },
            { name: "c.txt", status: "cancelled" },
            { name: "d.txt", status: "cancelled" },
          ]}
        />
      </MantineProvider>,
    );
    expect(
      screen.getByText("Upload cancelled — 2 of 4 files uploaded"),
    ).toBeInTheDocument();
    // No mention of "failed" — cancel is a deliberate action, not a failure.
    expect(screen.queryByText(/failed/i)).not.toBeInTheDocument();
  });

  it("shows both 'failed' and 'cancelled' counts when a batch had both", () => {
    render(
      <MantineProvider>
        <UploadSummary
          items={[
            { name: "a.txt", status: "done" },
            { name: "huge.zip", status: "error", error: "too big" },
            { name: "c.txt", status: "cancelled" },
          ]}
        />
      </MantineProvider>,
    );
    expect(screen.getByText(/1\/3 files uploaded — 1 failed, 1 cancelled/)).toBeInTheDocument();
  });
});
