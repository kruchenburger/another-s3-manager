import { describe, it, expect } from "vitest";
import { render, screen, fireEvent } from "@testing-library/react";
import { MantineProvider } from "@mantine/core";
import { VideoPreview } from "@/components/Preview/VideoPreview";

function renderPreview(url = "/api/buckets/x/download?path=broken.mp4") {
  return render(
    <MantineProvider>
      <VideoPreview url={url} />
    </MantineProvider>,
  );
}

describe("VideoPreview", () => {
  it("renders an Alert + Download fallback link when the video fails to load", () => {
    const { container } = renderPreview();
    const video = container.querySelector("video");
    expect(video).toBeTruthy();
    fireEvent.error(video!);
    expect(screen.getByText(/couldn't load this video/i)).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /download/i })).toHaveAttribute(
      "href",
      "/api/buckets/x/download?path=broken.mp4",
    );
  });

  it("resets the failed state when url changes (e.g. switching to a different video in the modal)", () => {
    const { container, rerender } = renderPreview();
    fireEvent.error(container.querySelector("video")!);
    expect(screen.getByText(/couldn't load this video/i)).toBeInTheDocument();

    rerender(
      <MantineProvider>
        <VideoPreview url="/api/buckets/x/download?path=good.mp4" />
      </MantineProvider>,
    );
    expect(container.querySelector("video")).toBeTruthy();
    expect(screen.queryByText(/couldn't load this video/i)).not.toBeInTheDocument();
  });
});
