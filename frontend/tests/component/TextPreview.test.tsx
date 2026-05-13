import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import { MantineProvider } from "@mantine/core";
import { TextPreview } from "@/components/Preview/TextPreview";

function renderPreview() {
  return render(
    <MantineProvider>
      <TextPreview url="/api/buckets/x/download?path=secret.txt" size={100} />
    </MantineProvider>,
  );
}

describe("TextPreview error rendering", () => {
  beforeEach(() => vi.restoreAllMocks());
  afterEach(() => vi.restoreAllMocks());

  it("surfaces the server detail on 403 instead of bare 'HTTP 403'", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue({
        ok: false,
        status: 403,
        statusText: "Forbidden",
        json: () => Promise.resolve({ detail: "You don't have access to this object" }),
        text: () => Promise.resolve(""),
      }),
    );
    renderPreview();
    await waitFor(() =>
      expect(screen.getByText(/you don't have access to this object/i)).toBeInTheDocument(),
    );
    expect(screen.queryByText(/^HTTP 403$/)).not.toBeInTheDocument();
  });

  it("renders the text body on 2xx", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue({
        ok: true,
        status: 200,
        text: () => Promise.resolve("hello world\nsecond line"),
      }),
    );
    renderPreview();
    await waitFor(() =>
      expect(screen.getByText(/hello world/)).toBeInTheDocument(),
    );
  });
});
