import { beforeEach, describe, expect, it, vi } from "vitest";
import {
  act,
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
} from "@testing-library/react";
import { MantineProvider } from "@mantine/core";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MoveDialog } from "@/components/FileBrowser/MoveDialog";
import * as api from "@/features/files/api/filesApi";
import type { MoveItem } from "@/types/api";
beforeEach(() => {
  cleanup();
  vi.restoreAllMocks();
});
function setup(items: MoveItem[] = [{ path: "a/x", kind: "folder" }]) {
  const onChoose = vi.fn();
  render(
    <QueryClientProvider
      client={
        new QueryClient({ defaultOptions: { queries: { retry: false } } })
      }
    >
      <MantineProvider>
        <MoveDialog
          bucket="b"
          role="r"
          path="a"
          items={items}
          onClose={vi.fn()}
          onChoose={onChoose}
        />
      </MantineProvider>
    </QueryClientProvider>,
  );
  return onChoose;
}
describe("Move picker", () => {
  it("Escape closes only the nested folder modal and preserves the move", async () => {
    vi.spyOn(api, "listFiles").mockResolvedValue({
      directories: [],
      files: [],
      truncated: false,
      next_token: null,
    });
    const close = vi.fn();
    const choose = vi.fn();
    render(
      <QueryClientProvider client={new QueryClient()}>
        <MantineProvider>
          <MoveDialog
            bucket="b"
            role="r"
            path="a"
            items={[{ path: "a/x", kind: "file" }]}
            onClose={close}
            onChoose={choose}
          />
        </MantineProvider>
      </QueryClientProvider>,
    );
    fireEvent.click(screen.getByRole("button", { name: "b" }));
    fireEvent.change(screen.getByLabelText("New name"), {
      target: { value: "new-x" },
    });
    fireEvent.click(screen.getByRole("button", { name: "New folder" }));
    const input = await screen.findByLabelText("Folder name");
    input.focus();
    fireEvent.keyDown(input, { key: "Escape", code: "Escape" });
    await waitFor(() =>
      expect(screen.queryByLabelText("Folder name")).not.toBeInTheDocument(),
    );
    expect(close).not.toHaveBeenCalled();
    expect(screen.getByLabelText("New name")).toHaveValue("new-x");
    fireEvent.click(screen.getByRole("button", { name: "Move here" }));
    expect(choose).toHaveBeenCalledWith({
      items: [{ path: "a/x", kind: "file", new_name: "new-x" }],
      destination: "",
    });
  });
  it("follows files-only pages, disables self/current and permits a different name", async () => {
    const list = vi
      .spyOn(api, "listFiles")
      .mockResolvedValueOnce({
        directories: [],
        files: [{ name: "f", is_directory: false, size: 1 }],
        truncated: true,
        next_token: "next",
      })
      .mockResolvedValue({
        directories: [{ name: "x", is_directory: true, size: 0 }],
        files: [],
        truncated: false,
        next_token: null,
      });
    const choose = setup();
    expect(screen.getByLabelText("New name")).toHaveValue("x");
    expect(screen.getByRole("button", { name: "Move here" })).toBeDisabled();
    fireEvent.click(await screen.findByRole("button", { name: "Load more" }));
    expect(
      await screen.findByRole("button", { name: "Open folder x" }),
    ).toBeDisabled();
    expect(list).toHaveBeenLastCalledWith("b", "r", "a", {
      continuationToken: "next",
    });
    fireEvent.change(screen.getByLabelText("New name"), {
      target: { value: "y" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Move here" }));
    expect(choose).toHaveBeenCalledWith({
      items: [{ path: "a/x", kind: "folder", new_name: "y" }],
      destination: "a",
    });
    expect(
      screen.queryByRole("button", { name: "Rename" }),
    ).not.toBeInTheDocument();
  });
  it("has no name field for multiple items and distinguishes failed continuation", async () => {
    vi.spyOn(api, "listFiles")
      .mockResolvedValueOnce({
        directories: [],
        files: [],
        truncated: true,
        next_token: "next",
      })
      .mockRejectedValue(new Error("Continuation failed"));
    setup([
      { path: "a/x", kind: "file" },
      { path: "a/y", kind: "file" },
    ]);
    expect(screen.queryByLabelText("New name")).not.toBeInTheDocument();
    fireEvent.click(await screen.findByRole("button", { name: "Load more" }));
    expect(await screen.findByText("Continuation failed")).toBeInTheDocument();
    expect(
      screen.queryByText("This folder has no subfolders."),
    ).not.toBeInTheDocument();
  });
  it("keeps existing names exact when moving without a new name", async () => {
    vi.spyOn(api, "listFiles").mockResolvedValue({
      directories: [],
      files: [],
      truncated: false,
      next_token: null,
    });
    const choose = setup([{ path: "a/ leading", kind: "file" }]);
    await act(async () =>
      fireEvent.click(screen.getByRole("button", { name: "b" })),
    );
    fireEvent.click(screen.getByRole("button", { name: "Move here" }));
    expect(choose).toHaveBeenCalledWith({
      items: [{ path: "a/ leading", kind: "file" }],
      destination: "",
    });
  });
});
