import {
  act,
  cleanup,
  render,
  screen,
  fireEvent,
  waitFor,
  within,
} from "@testing-library/react";
import { MantineProvider } from "@mantine/core";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { afterEach, describe, expect, it, vi } from "vitest";
import { MoveJobDetails } from "@/components/FileBrowser/MoveJobDetails";
import {
  MoveJobsPanel,
  MoveProgress,
  SUCCESS_AUTO_DISMISS_MS,
} from "@/components/FileBrowser/MoveProgress";
import type { MoveJob } from "@/types/api";
import * as jobsModule from "@/features/files/jobs/MoveJobsProvider";
import type { MoveRecord } from "@/features/files/jobs/MoveJobsProvider";
import * as api from "@/features/files/api/filesApi";
const record: MoveRecord = {
  job_id: "j",
  bucket: "b",
  role: "r",
  items: [{ path: "x", kind: "file" }],
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
  vi.useRealTimers();
});
function details(
  state: MoveJob["state"] = "failed_copy",
  delete_started: boolean | undefined = false,
  disableDeletion = false,
) {
  render(
    <QueryClientProvider
      client={
        new QueryClient({ defaultOptions: { queries: { retry: false } } })
      }
    >
      <MantineProvider>
        <MoveJobDetails
          record={{ ...record, snapshot: { ...job, state, delete_started } }}
          onClose={vi.fn()}
          disableDeletion={disableDeletion}
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
      // Pass undefined explicitly in the snapshot to cover legacy responses.
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
    details("cancelled_access", false, true);
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
        />
      </MantineProvider>,
    );
    expect(screen.getByRole("progressbar")).not.toHaveAttribute(
      "aria-valuenow",
    );
    expect(screen.getByText(/Copying 6.7 GB/)).toBeInTheDocument();
  });
  it("shows determinate deletion progress", () => {
    render(
      <MantineProvider>
        <MoveProgress
          record={{
            ...record,
            snapshot: {
              ...job,
              state: "running",
              phase: "delete",
              total: 4,
              done: 4,
              removed: 1,
            },
          }}
          onDetails={vi.fn()}
        />
      </MantineProvider>,
    );
    expect(screen.getByRole("progressbar")).toHaveAttribute(
      "aria-valuenow",
      "25",
    );
    expect(screen.getByText("Removing originals")).toBeInTheDocument();
  });
});
describe("move tray", () => {
  function entry(id: string, state: MoveJob["state"] = "running"): MoveRecord {
    return {
      ...record,
      job_id: id,
      items: [{ path: `parent/${id}`, kind: "file" }],
      snapshot: { ...job, job_id: id, state },
    };
  }
  function tray(initial: MoveRecord[]) {
    let jobs = initial;
    const dismiss = vi.fn();
    vi.spyOn(jobsModule, "useMoveJobs").mockImplementation(() => ({
      jobs,
      dismiss,
      add: vi.fn(),
      disableDeletion: false,
    }));
    const client = new QueryClient();
    const element = () => (
      <QueryClientProvider client={client}>
        <MantineProvider>
          <MoveJobsPanel />
        </MantineProvider>
      </QueryClientProvider>
    );
    const view = render(element());
    return {
      dismiss,
      update(next: MoveRecord[]) {
        jobs = next;
        view.rerender(element());
      },
    };
  }
  it("has one summary, newest-first rows, collapse and a guarded close", () => {
    const first = entry("first", "done");
    const second = { ...entry("second"), destination: "" };
    const third = {
      ...entry("third"),
      items: [...record.items, ...record.items],
    };
    const view = tray([first, second, third]);
    expect(screen.getAllByRole("status")).toHaveLength(1);
    expect(screen.getByRole("status")).toHaveTextContent("Moving… 1 of 3 done");
    expect(screen.getByRole("status")).toHaveAttribute("aria-live", "polite");
    const rows = screen.getAllByRole("listitem");
    expect(rows).toHaveLength(3);
    expect(rows[0]).toHaveTextContent("2 items → dest");
    expect(rows[1]).toHaveTextContent("second → /");
    expect(rows[2]).toHaveTextContent("first → dest");
    expect(
      screen.getByRole("button", { name: "Dismiss move result" }),
    ).toBeDisabled();
    fireEvent.click(screen.getByRole("button", { name: "Collapse move jobs" }));
    expect(screen.getByRole("status")).toBeVisible();
    expect(screen.queryByRole("list")).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Expand move jobs" }));
    expect(screen.getAllByRole("listitem")).toHaveLength(3);
    view.update([
      first,
      entry("second", "done"),
      entry("third", "failed_copy"),
    ]);
    expect(screen.getByRole("status")).toHaveTextContent(
      "2 done · 1 needs attention",
    );
    fireEvent.click(
      screen.getByRole("button", { name: "Dismiss move result" }),
    );
    expect(view.dismiss.mock.calls).toEqual([["first"], ["second"], ["third"]]);
  });
  it("opens the existing details for the chosen row", () => {
    tray([entry("first", "failed_copy"), entry("second", "failed_delete")]);
    fireEvent.click(
      within(screen.getAllByRole("listitem")[0]).getByRole("button", {
        name: "Details",
      }),
    );
    expect(
      screen.getByRole("dialog", { name: "Move details" }),
    ).toHaveTextContent("Some originals could not be removed");
    expect(
      screen.queryByRole("button", { name: "Remove partial copies" }),
    ).not.toBeInTheDocument();
  });
  it("waits for every success and does not restart on equivalent rerenders", () => {
    vi.useFakeTimers();
    const view = tray([entry("a", "done"), entry("b")]);
    act(() => vi.advanceTimersByTime(10_000));
    expect(view.dismiss).not.toHaveBeenCalled();
    view.update([entry("a", "done"), entry("b", "done")]);
    expect(screen.getByRole("status")).toHaveTextContent("2 moves done");
    act(() => vi.advanceTimersByTime(SUCCESS_AUTO_DISMISS_MS - 1));
    expect(view.dismiss).not.toHaveBeenCalled();
    view.update([entry("a", "done"), entry("b", "done")]);
    act(() => vi.advanceTimersByTime(1));
    expect(view.dismiss.mock.calls).toEqual([["a"], ["b"]]);
  });
  it("cancels the countdown for a new running job and starts a fresh interval", () => {
    vi.useFakeTimers();
    const view = tray([entry("a", "done")]);
    act(() => vi.advanceTimersByTime(4000));
    view.update([entry("a", "done"), entry("b")]);
    act(() => vi.advanceTimersByTime(10_000));
    expect(view.dismiss).not.toHaveBeenCalled();
    view.update([entry("a", "done"), entry("b", "done")]);
    act(() => vi.advanceTimersByTime(SUCCESS_AUTO_DISMISS_MS - 1));
    expect(view.dismiss).not.toHaveBeenCalled();
    act(() => vi.advanceTimersByTime(1));
    expect(view.dismiss).toHaveBeenCalledTimes(2);
  });
  it.each([
    "done_with_warnings",
    "failed_copy",
    "failed_delete",
    "cancelled_access",
    "unavailable",
  ] as const)("keeps %s visible", (state) => {
    vi.useFakeTimers();
    const problem =
      state === "unavailable"
        ? { ...entry("b", "done"), unavailable: "Result no longer available" }
        : entry("b", state);
    const view = tray([entry("a", "done"), problem]);
    act(() => vi.advanceTimersByTime(20_000));
    expect(view.dismiss).not.toHaveBeenCalled();
    expect(screen.getByRole("status")).toHaveTextContent(
      "1 done · 1 needs attention",
    );
    expect(screen.queryByRole("progressbar")).not.toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: "Dismiss move result" }),
    ).toBeEnabled();
    expect(
      screen.getByLabelText(
        state.startsWith("failed") ? "Move failed" : "Move needs attention",
      ),
    ).toBeInTheDocument();
  });
  it("treats a missing snapshot as running", () => {
    tray([{ ...record }]);
    expect(
      screen.getByRole("button", { name: "Dismiss move result" }),
    ).toBeDisabled();
    expect(screen.getByRole("status")).toHaveTextContent("Moving… 0 of 1 done");
  });
});
