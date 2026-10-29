import { act, cleanup, renderHook, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { beforeEach, afterEach, describe, expect, it, vi } from "vitest";
import type { ReactNode } from "react";
import { StrictMode } from "react";
import { MantineProvider } from "@mantine/core";
import {
  MoveJobsProvider,
  useMoveJobs,
  jobsStorageKey,
} from "@/features/files/jobs/MoveJobsProvider";
import * as api from "@/features/files/api/filesApi";
import { ApiError } from "@/utils/apiError";
import type { MoveJob } from "@/types/api";
import { showToast } from "@/utils/toast";
const auth = vi.hoisted(() => ({ username: "alice" as string | undefined }));
vi.mock("@/features/auth/hooks/useMe", () => ({
  useMe: () => ({
    data: auth.username
      ? { username: auth.username, disable_deletion: false }
      : undefined,
  }),
  meQueryKey: ["auth", "me"],
}));
vi.mock("@/utils/toast", () => ({ showToast: vi.fn() }));
const saved = {
  job_id: "j",
  bucket: "b",
  role: "r",
  items: [{ path: "x", kind: "file" as const }],
  destination: "target",
};
const snapshot: MoveJob = {
  job_id: "j",
  state: "done",
  phase: "delete",
  done: 1,
  total: 1,
  bytes_done: 3,
  bytes_total: 3,
  removed: 1,
  failures: [],
  failures_total: 0,
  failures_stored: 0,
  failures_offset: 0,
  next_failures_offset: null,
  result: { moved: 1 },
};
function setup(
  qc = new QueryClient({ defaultOptions: { queries: { retry: false } } }),
) {
  return renderHook(() => useMoveJobs(), {
    wrapper: ({ children }: { children: ReactNode }) => (
      <QueryClientProvider client={qc}>
        <MantineProvider>
          <MoveJobsProvider>{children}</MoveJobsProvider>
        </MantineProvider>
      </QueryClientProvider>
    ),
  });
}
beforeEach(() => {
  localStorage.clear();
  vi.restoreAllMocks();
  vi.mocked(showToast).mockClear();
  auth.username = "alice";
});
afterEach(() => {
  cleanup();
  vi.useRealTimers();
});
describe("app-level move jobs", () => {
  it("refreshes cached listings on a resumed terminal job even after its toast was shown", async () => {
    localStorage.setItem(
      jobsStorageKey("alice"),
      JSON.stringify({ version: 1, jobs: [{ ...saved, notified: true }] }),
    );
    vi.spyOn(api, "getJob").mockResolvedValue(snapshot);
    const qc = new QueryClient();
    qc.setQueryData(["files", "list", "r", "b", "cached"], 1);
    const hook = setup(qc);
    await waitFor(() =>
      expect(hook.result.current.jobs[0].snapshot?.state).toBe("done"),
    );
    expect(
      qc.getQueryState(["files", "list", "r", "b", "cached"])?.isInvalidated,
    ).toBe(true);
    expect(showToast).not.toHaveBeenCalled();
  });
  it("announces a cached terminal result only once under StrictMode", async () => {
    localStorage.setItem(
      jobsStorageKey("alice"),
      JSON.stringify({ version: 1, jobs: [saved] }),
    );
    vi.spyOn(api, "getJob").mockResolvedValue(snapshot);
    const qc = new QueryClient();
    qc.setQueryData(["move-job", "alice", "j"], snapshot);
    renderHook(() => useMoveJobs(), {
      wrapper: ({ children }: { children: ReactNode }) => (
        <StrictMode>
          <QueryClientProvider client={qc}>
            <MantineProvider>
              <MoveJobsProvider>{children}</MoveJobsProvider>
            </MantineProvider>
          </QueryClientProvider>
        </StrictMode>
      ),
    });
    await waitFor(() => expect(showToast).toHaveBeenCalled());
    expect(showToast).toHaveBeenCalledOnce();
  });
  it("persists, resumes with GET and invalidates all matching list/search paths", async () => {
    vi.spyOn(api, "getJob").mockResolvedValue(snapshot);
    const qc = new QueryClient();
    qc.setQueryData(["files", "list", "r", "b", "a"], 1);
    qc.setQueryData(["files", "search", "r", "b", "other", "term"], 2);
    qc.setQueryData(["files", "list", "other", "b", "a"], 3);
    const hook = setup(qc);
    act(() => hook.result.current.add(saved));
    await waitFor(() =>
      expect(hook.result.current.jobs[0].snapshot?.state).toBe("done"),
    );
    expect(
      qc.getQueryState(["files", "list", "r", "b", "a"])?.isInvalidated,
    ).toBe(true);
    expect(
      qc.getQueryState(["files", "search", "r", "b", "other", "term"])
        ?.isInvalidated,
    ).toBe(true);
    expect(
      qc.getQueryState(["files", "list", "other", "b", "a"])?.isInvalidated,
    ).toBe(false);
    expect(localStorage.getItem(jobsStorageKey("alice"))).toContain(
      '"job_id":"j"',
    );
    hook.unmount();
    const start = vi.spyOn(api, "startMove");
    setup();
    await waitFor(() => expect(api.getJob).toHaveBeenCalledTimes(2));
    expect(start).not.toHaveBeenCalled();
  });
  it("stops on 404 without restarting the move", async () => {
    localStorage.setItem(
      jobsStorageKey("alice"),
      JSON.stringify({ version: 1, jobs: [saved] }),
    );
    vi.spyOn(api, "getJob").mockRejectedValue(new ApiError(404, "Not found"));
    const start = vi.spyOn(api, "startMove");
    const { result } = setup();
    await waitFor(() =>
      expect(result.current.jobs[0].unavailable).toBe(
        "Result no longer available",
      ),
    );
    expect(start).not.toHaveBeenCalled();
  });
  it("survives corrupt and unavailable storage", async () => {
    localStorage.setItem(jobsStorageKey("alice"), "broken");
    vi.spyOn(api, "getJob").mockResolvedValue(snapshot);
    const hook = setup();
    expect(hook.result.current.jobs).toEqual([]);
    vi.spyOn(localStorage, "setItem").mockImplementation(() => {
      throw new Error("denied");
    });
    act(() => hook.result.current.add(saved));
    await waitFor(() =>
      expect(hook.result.current.jobs[0].snapshot?.state).toBe("done"),
    );
  });
  it("polls at one second, backs off offline, and stops at a terminal result", async () => {
    vi.useFakeTimers();
    const get = vi
      .spyOn(api, "getJob")
      .mockResolvedValueOnce({ ...snapshot, state: "running", phase: "copy" })
      .mockRejectedValueOnce(new TypeError("offline"))
      .mockResolvedValue(snapshot);
    const hook = setup();
    await act(async () => hook.result.current.add(saved));
    expect(get).toHaveBeenCalledTimes(1);
    await act(async () => {
      await vi.advanceTimersByTimeAsync(1000);
    });
    expect(get).toHaveBeenCalledTimes(2);
    await act(async () => {
      await vi.advanceTimersByTimeAsync(1999);
    });
    expect(get).toHaveBeenCalledTimes(2);
    await act(async () => {
      await vi.advanceTimersByTimeAsync(1);
    });
    expect(get).toHaveBeenCalledTimes(3);
    expect(hook.result.current.jobs[0].snapshot?.state).toBe("done");
    await act(async () => {
      await vi.advanceTimersByTimeAsync(10_000);
    });
    expect(get).toHaveBeenCalledTimes(3);
    expect(showToast).toHaveBeenCalledOnce();
  });
  it.each([401, 403, 404])(
    "does not keep polling after HTTP %s",
    async (status) => {
      vi.useFakeTimers();
      const get = vi
        .spyOn(api, "getJob")
        .mockRejectedValue(new ApiError(status, "denied"));
      const qc = new QueryClient();
      const invalidate = vi.spyOn(qc, "invalidateQueries");
      const hook = setup(qc);
      await act(async () => hook.result.current.add(saved));
      await act(async () => {
        await vi.advanceTimersByTimeAsync(15_000);
      });
      expect(get).toHaveBeenCalledOnce();
      if (status === 401)
        expect(invalidate).toHaveBeenCalledWith({ queryKey: ["auth", "me"] });
      else expect(hook.result.current.jobs[0].unavailable).toBeTruthy();
    },
  );
  it("isolates jobs on logout and another user's login", async () => {
    const get = vi
      .spyOn(api, "getJob")
      .mockResolvedValue({ ...snapshot, state: "running" });
    const hook = setup();
    await act(async () => hook.result.current.add(saved));
    await waitFor(() => expect(get).toHaveBeenCalledOnce());
    auth.username = undefined;
    hook.rerender();
    expect(hook.result.current.jobs).toEqual([]);
    auth.username = "bob";
    hook.rerender();
    expect(hook.result.current.jobs).toEqual([]);
    expect(localStorage.getItem(jobsStorageKey("alice"))).toContain(
      '"job_id":"j"',
    );
    expect(localStorage.getItem(jobsStorageKey("bob"))).not.toContain(
      '"job_id":"j"',
    );
  });
});
