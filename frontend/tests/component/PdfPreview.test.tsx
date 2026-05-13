import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import { MantineProvider } from "@mantine/core";
import { PdfPreview } from "@/components/Preview/PdfPreview";

function renderPreview() {
  return render(
    <MantineProvider>
      <PdfPreview url="/api/buckets/x/download?path=doc.pdf" />
    </MantineProvider>,
  );
}

describe("PdfPreview", () => {
  beforeEach(() => vi.restoreAllMocks());
  afterEach(() => vi.restoreAllMocks());

  it("renders the iframe when HEAD pre-fetch succeeds", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue({
        ok: true,
        status: 200,
        statusText: "OK",
        json: () => Promise.resolve({}),
      }),
    );
    const { container } = renderPreview();
    await waitFor(() => expect(container.querySelector("iframe")).toBeInTheDocument());
    expect(screen.queryByText(/couldn't load this pdf/i)).not.toBeInTheDocument();
  });

  it("renders Alert + Download fallback when HEAD pre-fetch fails", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue({
        ok: false,
        status: 403,
        statusText: "Forbidden",
        json: () => Promise.resolve({ detail: "Access denied" }),
      }),
    );
    const { container } = renderPreview();
    await waitFor(() =>
      expect(screen.getByText(/couldn't load this pdf/i)).toBeInTheDocument(),
    );
    expect(screen.getByText(/access denied/i)).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /download/i })).toHaveAttribute(
      "href",
      "/api/buckets/x/download?path=doc.pdf",
    );
    expect(container.querySelector("iframe")).not.toBeInTheDocument();
  });
});
