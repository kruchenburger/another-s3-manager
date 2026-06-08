import { describe, it, expect, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import { MantineProvider } from "@mantine/core";
import { PreviewModal } from "@/components/Preview/PreviewModal";

// Mock useConfig so we can control auto_inline_extensions per test.
vi.mock("@/hooks/useConfig", () => ({
  useConfig: vi.fn(),
}));

// Stub heavy preview children to keep tests fast and focused on routing logic.
vi.mock("@/components/Preview/ImagePreview", () => ({
  ImagePreview: ({ url, alt }: { url: string; alt: string }) => (
    <div data-testid="image-preview" data-url={url} data-alt={alt} />
  ),
}));
vi.mock("@/components/Preview/VideoPreview", () => ({
  VideoPreview: ({ url }: { url: string }) => (
    <div data-testid="video-preview" data-url={url} />
  ),
}));
vi.mock("@/components/Preview/PdfPreview", () => ({
  PdfPreview: ({ url }: { url: string }) => (
    <div data-testid="pdf-preview" data-url={url} />
  ),
}));
vi.mock("@/components/Preview/TextPreview", () => ({
  TextPreview: ({ url, size }: { url: string; size: number }) => (
    <div data-testid="text-preview" data-url={url} data-size={size} />
  ),
}));

import { useConfig } from "@/hooks/useConfig";

const mockUseConfig = vi.mocked(useConfig);

function renderModal(filename: string, autoInlineExts: string[]) {
  mockUseConfig.mockReturnValue({
    data: { auto_inline_extensions: autoInlineExts } as never,
  } as never);

  return render(
    <MantineProvider>
      <PreviewModal
        opened
        onClose={vi.fn()}
        filename={filename}
        url="/api/buckets/b/download?path=file"
        size={1024}
      />
    </MantineProvider>,
  );
}

describe("PreviewModal — type routing via auto_inline_extensions", () => {
  it(".ts with auto_inline_extensions=['ts'] renders text preview", () => {
    renderModal("script.ts", ["ts"]);
    expect(screen.getByTestId("text-preview")).toBeInTheDocument();
    expect(screen.queryByTestId("image-preview")).not.toBeInTheDocument();
    expect(screen.queryByTestId("video-preview")).not.toBeInTheDocument();
    expect(screen.queryByTestId("pdf-preview")).not.toBeInTheDocument();
  });

  it(".md still renders text preview with a custom admin list (defaults always on)", () => {
    renderModal("readme.md", ["ts"]);
    expect(screen.getByTestId("text-preview")).toBeInTheDocument();
  });

  it("an extension in neither the defaults nor the admin list shows the unsupported fallback", () => {
    renderModal("archive.bin", ["ts"]);
    expect(screen.queryByTestId("text-preview")).not.toBeInTheDocument();
    expect(
      screen.getByText(/This file type cannot be previewed/),
    ).toBeInTheDocument();
  });

  it(".png with auto_inline_extensions=['ts'] renders image preview (media always wins)", () => {
    renderModal("photo.png", ["ts"]);
    expect(screen.getByTestId("image-preview")).toBeInTheDocument();
    expect(screen.queryByTestId("text-preview")).not.toBeInTheDocument();
  });
});
