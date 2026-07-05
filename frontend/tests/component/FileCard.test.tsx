import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, fireEvent } from "@testing-library/react";
import { MantineProvider } from "@mantine/core";

vi.mock("@/features/auth/hooks/useMe", () => ({
  useMe: () => ({ data: { disable_deletion: false } }),
}));
vi.mock("@/hooks/useConfig", () => ({
  useConfig: () => ({ data: { auto_inline_extensions: [] } }),
}));
vi.mock("@/features/files/hooks/usePresignedUrl", () => ({
  usePresignedUrl: vi.fn(),
}));

import { FileCard } from "@/components/FileBrowser/FileCard";
import { usePresignedUrl } from "@/features/files/hooks/usePresignedUrl";

const baseProps = {
  index: 0,
  selected: false,
  onToggleSelect: vi.fn(),
  onNavigate: vi.fn(),
  onDownload: vi.fn(),
  onCopyUrl: vi.fn(),
  onPreview: vi.fn(),
  onDelete: vi.fn(),
  bucket: "b",
  roleId: "r",
  path: "",
};

function renderCard(file: React.ComponentProps<typeof FileCard>["file"]) {
  return render(
    <MantineProvider>
      <FileCard {...baseProps} file={file} />
    </MantineProvider>,
  );
}

describe("FileCard image thumbnails", () => {
  beforeEach(() => vi.clearAllMocks());

  it("renders <img> for .jpg with the presigned URL", () => {
    vi.mocked(usePresignedUrl).mockReturnValue({
      data: {
        url: "https://signed/photo.jpg",
        expires_at: "2026-05-05T12:00:00+00:00",
      },
      isSuccess: true,
    } as never);
    renderCard({ name: "photo.jpg", is_directory: false, size: 1024 });
    const img = screen.getByRole("img", { name: /photo.jpg/i });
    expect(img).toHaveAttribute("src", "https://signed/photo.jpg");
    expect(img).toHaveAttribute("loading", "lazy");
    expect(img).toHaveAttribute("decoding", "async");
  });

  it("renders generic icon for .pdf (not in image/video whitelist)", () => {
    vi.mocked(usePresignedUrl).mockReturnValue({
      data: undefined,
      isSuccess: false,
    } as never);
    renderCard({ name: "doc.pdf", is_directory: false, size: 1024 });
    expect(screen.queryByRole("img", { name: /doc.pdf/i })).not.toBeInTheDocument();
    expect(screen.getByText("doc.pdf")).toBeInTheDocument();
  });

  it("renders generic icon while presigned URL is still loading", () => {
    vi.mocked(usePresignedUrl).mockReturnValue({
      data: undefined,
      isSuccess: false,
    } as never);
    renderCard({ name: "photo.png", is_directory: false, size: 1024 });
    expect(screen.queryByRole("img", { name: /photo.png/i })).not.toBeInTheDocument();
  });
});

describe("FileCard video thumbnails", () => {
  beforeEach(() => vi.clearAllMocks());

  it("renders <video> for .mp4 with preload=metadata, muted, playsInline", () => {
    vi.mocked(usePresignedUrl).mockReturnValue({
      data: {
        url: "https://signed/clip.mp4",
        expires_at: "2026-05-05T12:00:00+00:00",
      },
      isSuccess: true,
    } as never);
    const { container } = renderCard({
      name: "clip.mp4",
      is_directory: false,
      size: 1024,
    });
    const video = container.querySelector("video");
    expect(video).not.toBeNull();
    expect(video).toHaveAttribute("src", "https://signed/clip.mp4");
    expect(video).toHaveAttribute("preload", "metadata");
    expect(video?.muted).toBe(true);
    // React renders the boolean attribute as "playsinline" lowercase in DOM.
    expect(video?.hasAttribute("playsinline")).toBe(true);
  });

  it("falls back to icon for .mp4 while presigned URL is loading", () => {
    vi.mocked(usePresignedUrl).mockReturnValue({
      data: undefined,
      isSuccess: false,
    } as never);
    const { container } = renderCard({
      name: "clip.mp4",
      is_directory: false,
      size: 1024,
    });
    expect(container.querySelector("video")).toBeNull();
  });
});

describe("FileCard shift-select text-selection guard", () => {
  beforeEach(() => vi.clearAllMocks());

  // Shift+click range-select must not start the browser's native text
  // selection across cards. fireEvent returns false when preventDefault ran.
  it("prevents default on shift+mousedown of the checkbox", () => {
    vi.mocked(usePresignedUrl).mockReturnValue({
      data: undefined,
      isSuccess: false,
    } as never);
    renderCard({ name: "doc.pdf", is_directory: false, size: 1024 });
    const notCancelled = fireEvent.mouseDown(screen.getByLabelText("Select doc.pdf"), {
      shiftKey: true,
    });
    expect(notCancelled).toBe(false);
  });

  it("leaves plain mousedown un-prevented (filenames stay selectable)", () => {
    vi.mocked(usePresignedUrl).mockReturnValue({
      data: undefined,
      isSuccess: false,
    } as never);
    renderCard({ name: "doc.pdf", is_directory: false, size: 1024 });
    const notCancelled = fireEvent.mouseDown(screen.getByLabelText("Select doc.pdf"), {
      shiftKey: false,
    });
    expect(notCancelled).toBe(true);
  });

  // The mousedown preventDefault must NOT break selection: shift+click still has
  // to fire onToggleSelect with shiftKey=true so range-select works.
  it("still fires onToggleSelect(name, true) on shift+click", () => {
    vi.mocked(usePresignedUrl).mockReturnValue({
      data: undefined,
      isSuccess: false,
    } as never);
    renderCard({ name: "doc.pdf", is_directory: false, size: 1024 });
    fireEvent.click(screen.getByLabelText("Select doc.pdf"), { shiftKey: true });
    expect(baseProps.onToggleSelect).toHaveBeenCalledWith("doc.pdf", true);
  });
});
