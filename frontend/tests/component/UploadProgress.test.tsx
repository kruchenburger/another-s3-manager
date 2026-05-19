import { describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MantineProvider } from "@mantine/core";
import { UploadProgress } from "@/components/Upload/UploadProgress";

describe("UploadProgress", () => {
  describe("multi-file batch", () => {
    it("shows 'Uploading 3 files' headline", () => {
      render(
        <MantineProvider>
          <UploadProgress
            items={[
              { name: "a.txt", status: "uploading" },
              { name: "b.txt", status: "pending" },
              { name: "c.txt", status: "pending" },
            ]}
          />
        </MantineProvider>,
      );
      expect(screen.getByText(/Uploading 3 files/)).toBeInTheDocument();
      expect(screen.getByText(/0\/3/)).toBeInTheDocument();
    });

    it("shows error count when failures occur (settled includes done + errors)", () => {
      render(
        <MantineProvider>
          <UploadProgress
            items={[
              { name: "a.txt", status: "done" },
              { name: "b.txt", status: "error", error: "boom" },
              { name: "c.txt", status: "done" },
            ]}
          />
        </MantineProvider>,
      );
      // Counter shows settled / total, where settled = done + error + cancelled.
      // 2 done + 1 error = 3 settled out of 3 total.
      expect(screen.getByText(/3\/3.*1 failed/)).toBeInTheDocument();
    });

    it("renders the current file's name (no inline percent in multi-file mode)", () => {
      render(
        <MantineProvider>
          <UploadProgress
            items={[
              { name: "first.zip", status: "done" },
              { name: "big-video.mp4", status: "uploading", progress: 42 },
              { name: "later.txt", status: "pending" },
            ]}
          />
        </MantineProvider>,
      );
      // Current filename appears below the bar.
      expect(screen.getByText("big-video.mp4")).toBeInTheDocument();
      // The "42%" inline label is reserved for single-file batches.
      expect(screen.queryByText("42%")).not.toBeInTheDocument();
    });
  });

  describe("single-file batch", () => {
    it("uses singular 'Uploading 1 file'", () => {
      render(
        <MantineProvider>
          <UploadProgress items={[{ name: "x.txt", status: "uploading", progress: 0 }]} />
        </MantineProvider>,
      );
      expect(screen.getByText(/Uploading 1 file$/)).toBeInTheDocument();
    });

    it("hides the N/M counter for single-file batch (counter would just say 0/1)", () => {
      render(
        <MantineProvider>
          <UploadProgress items={[{ name: "x.txt", status: "uploading", progress: 30 }]} />
        </MantineProvider>,
      );
      expect(screen.queryByText(/0\/1/)).not.toBeInTheDocument();
    });

    it("shows the filename + byte percent under the bar so the user sees progress", () => {
      render(
        <MantineProvider>
          <UploadProgress
            items={[{ name: "huge.zip", status: "uploading", progress: 42 }]}
          />
        </MantineProvider>,
      );
      expect(screen.getByText("huge.zip")).toBeInTheDocument();
      expect(screen.getByText("42%")).toBeInTheDocument();
    });
  });

  describe("cancel button", () => {
    it("renders and invokes onCancel when clicked", async () => {
      const onCancel = vi.fn();
      render(
        <MantineProvider>
          <UploadProgress
            items={[{ name: "x.txt", status: "uploading", progress: 10 }]}
            onCancel={onCancel}
          />
        </MantineProvider>,
      );
      const button = screen.getByRole("button", { name: /cancel upload/i });
      expect(button).toBeInTheDocument();
      await userEvent.click(button);
      expect(onCancel).toHaveBeenCalledTimes(1);
    });

    it("is hidden when onCancel is not provided (final summary state)", () => {
      render(
        <MantineProvider>
          <UploadProgress items={[{ name: "x.txt", status: "done" }]} />
        </MantineProvider>,
      );
      expect(screen.queryByRole("button", { name: /cancel upload/i })).not.toBeInTheDocument();
    });
  });
});
