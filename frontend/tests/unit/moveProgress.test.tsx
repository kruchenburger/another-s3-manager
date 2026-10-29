import {
  cleanup,
  render,
  screen,
  fireEvent,
  waitFor,
} from "@testing-library/react";
import { MantineProvider } from "@mantine/core";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { afterEach, describe, expect, it, vi } from "vitest";
import { MoveJobDetails } from "@/components/FileBrowser/MoveJobDetails";
import { MoveProgress } from "@/components/FileBrowser/MoveProgress";
import type { MoveJob } from "@/types/api";
import * as api from "@/features/files/api/filesApi";
const record = {
  job_id: "j",
  bucket: "b",
  role: "r",
  items: [{ path: "x", kind: "file" as const }],
  destination: "dest",
};
const job: MoveJob = {
  job_id: "j",
  state: "failed_copy",
  phase: "copy",
  delete_started: false,
  done: 0,
  total: 1,
  bytes_done: 0,
  bytes_total: 7_200_000_000,
  removed: 0,
  failures: [
    { code: "AccessDenied", message: "Access denied", phase: "copy", key: "x" },
  ],
  failures_total: 101,
  failures_stored: 101,
  failures_offset: 0,
  next_failures_offset: 100,
  result: { moved: 0 },
};
afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});
function details(state: MoveJob["state"] = "failed_copy") {
  render(
    <QueryClientProvider
      client={
        new QueryClient({ defaultOptions: { queries: { retry: false } } })
      }
    >
      <MantineProvider>
        <MoveJobDetails
          record={{ ...record, snapshot: { ...job, state } }}
          onClose={vi.fn()}
          disableDeletion={false}
        />
      </MantineProvider>
    </QueryClientProvider>,
  );
}
describe("move results", () => {
  it("loads the next failures page and runs job-scoped cleanup", async () => {
    vi.spyOn(api, "getJob").mockResolvedValue({
      ...job,
      failures_offset: 100,
      next_failures_offset: null,
      failures: [
        { code: "OTHER", message: "Second page", phase: "copy", key: "y" },
      ],
    });
    vi.spyOn(api, "cleanupJob").mockResolvedValue({ removed: 2, failures: [] });
    details();
    expect(screen.getByText(/originals are untouched/i)).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Load more failures" }));
    expect(await screen.findByText(/Second page/)).toBeInTheDocument();
    expect(api.getJob).toHaveBeenCalledWith("j", 100);
    fireEvent.click(
      screen.getByRole("button", { name: "Remove partial copies" }),
    );
    await waitFor(() => expect(api.cleanupJob).toHaveBeenCalledWith("j"));
    expect(
      await screen.findByText(/Removed 2 partial copies/),
    ).toBeInTheDocument();
  });
  it.each(["done", "done_with_warnings", "failed_delete"] as const)(
    "does not offer cleanup after %s",
    (state) => {
      details(state);
      expect(
        screen.queryByRole("button", { name: "Remove partial copies" }),
      ).not.toBeInTheDocument();
    },
  );
  it.each([false, true, undefined])(
    "offers cancelled cleanup only before deletion: %s",
    async (delete_started) => {
      const cleanup = vi
        .spyOn(api, "cleanupJob")
        .mockResolvedValue({ removed: 1, failures: [] });
      render(
        <QueryClientProvider client={new QueryClient()}>
          <MantineProvider>
            <MoveJobDetails
              record={{
                ...record,
                snapshot: { ...job, state: "cancelled_access", delete_started },
              }}
              onClose={vi.fn()}
              disableDeletion={false}
            />
          </MantineProvider>
        </QueryClientProvider>,
      );
      const button = screen.queryByRole("button", {
        name: "Remove partial copies",
      });
      if (delete_started === false) {
        expect(button).toBeInTheDocument();
        fireEvent.click(button!);
        await waitFor(() => expect(cleanup).toHaveBeenCalledWith("j"));
      } else expect(button).not.toBeInTheDocument();
    },
  );
  it("does not offer cleanup when deletion is disabled", () => {
    render(
      <QueryClientProvider client={new QueryClient()}>
        <MantineProvider>
          <MoveJobDetails
            record={{
              ...record,
              snapshot: { ...job, state: "cancelled_access" },
            }}
            onClose={vi.fn()}
            disableDeletion
          />
        </MantineProvider>
      </QueryClientProvider>,
    );
    expect(
      screen.queryByRole("button", { name: "Remove partial copies" }),
    ).not.toBeInTheDocument();
  });
  it("renders a live indeterminate single-object copy", () => {
    render(
      <MantineProvider>
        <MoveProgress
          record={{ ...record, snapshot: { ...job, state: "running" } }}
          onDetails={vi.fn()}
          onDismiss={vi.fn()}
        />
      </MantineProvider>,
    );
    expect(screen.getByRole("status")).toHaveAttribute("aria-live", "polite");
    expect(screen.getByText(/Copying 6.7 GB/)).toBeInTheDocument();
    expect(screen.getByText("Originals removed: 0 / 1")).toBeInTheDocument();
  });
});
