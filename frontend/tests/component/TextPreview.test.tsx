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

  it("renders an Alert + Download fallback link on error (not bare red text)", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue({
        ok: false,
        status: 403,
        statusText: "Forbidden",
        json: () => Promise.resolve({ detail: "Access denied" }),
      }),
    );
    renderPreview();
    await waitFor(() =>
      expect(screen.getByText(/couldn't load this text file/i)).toBeInTheDocument(),
    );
    expect(screen.getByText(/access denied/i)).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /download/i })).toHaveAttribute(
      "href",
      "/api/buckets/x/download?path=secret.txt",
    );
  });

  it("does not update state after unmount (cancellation flag)", async () => {
    // Hold the fetch pending so we can unmount before it resolves.
    let resolveFetch!: (value: Response) => void;
    const pendingFetch = new Promise<Response>((resolve) => {
      resolveFetch = resolve;
    });
    vi.stubGlobal("fetch", vi.fn().mockReturnValue(pendingFetch));
    const consoleError = vi.spyOn(console, "error").mockImplementation(() => {});

    const { unmount } = renderPreview();
    unmount();

    // Resolve fetch after unmount — should be ignored by the cancellation flag.
    resolveFetch({
      ok: true,
      status: 200,
      text: () => Promise.resolve("ignored content"),
    } as Response);
    await new Promise((r) => setTimeout(r, 50));

    // React would have logged "Can't perform a React state update on an
    // unmounted component" if the cancellation flag was missing.
    expect(consoleError).not.toHaveBeenCalledWith(
      expect.stringContaining("unmounted component"),
    );
    consoleError.mockRestore();
  });

  it("oversized file shows a failed state with a Download anchor (no fetch)", async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
    render(
      <MantineProvider>
        <TextPreview url="/api/buckets/x/download?path=big.txt" size={10 * 1024 * 1024} />
      </MantineProvider>,
    );
    await waitFor(() =>
      expect(screen.getByText(/file too large for preview/i)).toBeInTheDocument(),
    );
    expect(screen.getByRole("link", { name: /download/i })).toHaveAttribute(
      "href",
      "/api/buckets/x/download?path=big.txt",
    );
    expect(fetchMock).not.toHaveBeenCalled();
  });
});
