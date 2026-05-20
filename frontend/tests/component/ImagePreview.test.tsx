import { describe, it, expect } from "vitest";
import { render, screen, fireEvent } from "@testing-library/react";
import { MantineProvider } from "@mantine/core";
import { ImagePreview } from "@/components/Preview/ImagePreview";

function renderPreview(url = "/api/buckets/x/download?path=broken.png", alt = "broken.png") {
  return render(
    <MantineProvider>
      <ImagePreview url={url} alt={alt} />
    </MantineProvider>,
  );
}

describe("ImagePreview", () => {
  it("renders the image initially", () => {
    renderPreview();
    expect(screen.getByRole("img", { name: "broken.png" })).toBeInTheDocument();
    expect(screen.queryByText(/couldn't load this image/i)).not.toBeInTheDocument();
  });

  it("renders an Alert + Download fallback link when the image fails to load", () => {
    renderPreview();
    const img = screen.getByRole("img", { name: "broken.png" });
    fireEvent.error(img);
    expect(screen.getByText(/couldn't load this image/i)).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /download/i })).toHaveAttribute(
      "href",
      "/api/buckets/x/download?path=broken.png",
    );
  });

  it("resets the failed state when url changes (e.g. switching to a different image in the modal)", () => {
    const { rerender } = renderPreview();
    fireEvent.error(screen.getByRole("img", { name: "broken.png" }));
    expect(screen.getByText(/couldn't load this image/i)).toBeInTheDocument();

    rerender(
      <MantineProvider>
        <ImagePreview url="/api/buckets/x/download?path=good.png" alt="good.png" />
      </MantineProvider>,
    );
    expect(screen.getByRole("img", { name: "good.png" })).toBeInTheDocument();
    expect(screen.queryByText(/couldn't load this image/i)).not.toBeInTheDocument();
  });

  it("renders with object-fit: contain so non-square images aren't cropped at the edges", () => {
    // Mantine <Image fit="contain"> writes the value into the
    // --image-object-fit inline CSS custom property on the <img> element.
    // Regression guard for the user-reported "image cropped by edges in
    // preview modal" complaint — if a future refactor flips back to the
    // Mantine default (object-fit: cover), this test catches it.
    renderPreview();
    const img = screen.getByRole("img", { name: "broken.png" });
    expect(img.getAttribute("style") ?? "").toContain("--image-object-fit: contain");
  });
});
