import { beforeEach, describe, expect, it, vi } from "vitest";
import {
  fireEvent,
  render,
  screen,
  waitFor,
  cleanup,
} from "@testing-library/react";
import { MantineProvider } from "@mantine/core";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { NewFolderModal } from "@/components/FileBrowser/NewFolderModal";
import * as api from "@/features/files/api/filesApi";
import { ApiError } from "@/utils/apiError";
beforeEach(() => {
  cleanup();
  vi.restoreAllMocks();
});
function setup() {
  return render(
    <QueryClientProvider client={new QueryClient()}>
      <MantineProvider>
        <NewFolderModal opened bucket="b" role="r" path="a" onClose={vi.fn()} />
      </MantineProvider>
    </QueryClientProvider>,
  );
}
describe("New folder", () => {
  it("validates before sending and displays server conflict messages", async () => {
    const create = vi
      .spyOn(api, "createFolder")
      .mockRejectedValue(
        new ApiError(409, "Conflict", {
          detail: { message: "A file already exists with this name" },
        }),
      );
    setup();
    fireEvent.change(screen.getByLabelText("Folder name"), {
      target: { value: "bad/name" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Create folder" }));
    expect(create).not.toHaveBeenCalled();
    expect(await screen.findByText(/Use 1–255/)).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText("Folder name"), {
      target: { value: "valid" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Create folder" }));
    expect(
      await screen.findByText("A file already exists with this name"),
    ).toBeInTheDocument();
    expect(create).toHaveBeenCalledWith("b", "r", "a/valid");
  });
  it("creates and closes on success", async () => {
    vi.spyOn(api, "createFolder").mockResolvedValue({ path: "a/new/" });
    setup();
    fireEvent.change(screen.getByLabelText("Folder name"), {
      target: { value: "new" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Create folder" }));
    await waitFor(() =>
      expect(api.createFolder).toHaveBeenCalledWith("b", "r", "a/new"),
    );
  });
});
