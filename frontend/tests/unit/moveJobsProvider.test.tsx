import {
  act,
  cleanup,
  renderHook,
  waitFor,
  screen,
  fireEvent,
} from "@testing-library/react";
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
import { notifications } from "@mantine/notifications";
const auth = vi.hoisted(() => ({ username: "alice" as string | undefined }));
vi.mock("@/features/auth/hooks/useMe", () => ({
  useMe: () => ({
    data: auth.username
      ? { username: auth.username, disable_deletion: false }
      : undefined,
  }),
  meQueryKey: ["auth", "me"],
}));
vi.mock("@/utils/toast", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/utils/toast")>();
  return { ...actual, showToast: vi.fn(actual.showToast) };
});
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
  it("keeps independent tab jobs on reload and syncs storage changes and removals", async () => {
    vi.spyOn(api, "getJob").mockResolvedValue({
      ...snapshot,
      state: "running",
    });
    const first = setup();
    const second = setup();
    act(() => first.result.current.add(saved));
    act(() => second.result.current.add({ ...saved, job_id: "k" }));
    first.unmount();
    second.unmount();
    const resumed = setup();
    expect(resumed.result.current.jobs.map((j) => j.job_id).sort()).toEqual([
      "j",
      "k",
    ]);
    const key = Array.from({ length: localStorage.length }, (_, i) =>
      localStorage.key(i)!,
    ).find((k) => k.includes("v2") && k.endsWith(":j"))!;
    expect(key).toBeTruthy();
    const otherKey = key.slice(0, -1) + "remote";
    const remote = { ...saved, job_id: "remote" };
    localStorage.setItem(otherKey, JSON.stringify(remote));
    act(() =>
      window.dispatchEvent(
        new StorageEvent("storage", {
          key: otherKey,
          newValue: JSON.stringify(remote),
        }),
      ),
    );
    expect(resumed.result.current.jobs.map((j) => j.job_id)).toContain(
      "remote",
    );
    localStorage.setItem(
      otherKey,
      JSON.stringify({ ...remote, notified: true }),
    );
    act(() =>
      window.dispatchEvent(
        new StorageEvent("storage", {
          key: otherKey,
          newValue: localStorage.getItem(otherKey),
        }),
      ),
    );
    expect(
      resumed.result.current.jobs.find((j) => j.job_id === "remote")?.notified,
    ).toBe(true);
    localStorage.removeItem(key);
    act(() =>
      window.dispatchEvent(
        new StorageEvent("storage", { key, newValue: null }),
      ),
    );
    expect(resumed.result.current.jobs.map((j) => j.job_id)).not.toContain("j");
    expect(localStorage.getItem(key)).toBeNull();
    act(() => resumed.result.current.dismiss("remote"));
    expect(localStorage.getItem(otherKey)).toBeNull();
    localStorage.clear();
    act(() => window.dispatchEvent(new StorageEvent("storage", { key: null })));
    expect(resumed.result.current.jobs).toEqual([]);
  });
  it.each(["ROLE_NOT_FOUND", "ROLE_REQUIRED"])(
    "stops and exposes dismiss after HTTP 400 %s with stale progress",
    async (code) => {
      vi.useFakeTimers();
      const get = vi
        .spyOn(api, "getJob")
        .mockResolvedValueOnce({ ...snapshot, state: "running" })
        .mockRejectedValue(
          new ApiError(400, "Bad Request", {
            detail: { code, message: "Role unavailable" },
          }),
        );
      const hook = setup();
      await act(async () => hook.result.current.add(saved));
      await act(async () => {
        await vi.advanceTimersByTimeAsync(1000);
      });
      expect(hook.result.current.jobs[0].unavailable).toContain(code);
      expect(screen.getByText(new RegExp(code))).toBeInTheDocument();
      await act(async () => {
        await vi.advanceTimersByTimeAsync(60_000);
      });
      expect(get).toHaveBeenCalledTimes(2);
      fireEvent.click(
        screen.getByRole("button", { name: "Dismiss move result" }),
      );
      expect(hook.result.current.jobs).toEqual([]);
    },
  );
  it("keeps retrying other HTTP 400 errors", async () => {
    vi.useFakeTimers();
    const get = vi.spyOn(api, "getJob").mockRejectedValue(
      new ApiError(400, "Bad Request", {
        detail: { code: "OTHER", message: "Try later" },
      }),
    );
    const hook = setup();
    await act(async () => hook.result.current.add(saved));
    await act(async () => {
      await vi.advanceTimersByTimeAsync(30_000);
    });
    expect(get.mock.calls.length).toBeGreaterThan(1);
    expect(hook.result.current.jobs[0].unavailable).toBeUndefined();
  });
  it.each(["getItem", "key", "removeItem"] as const)(
    "survives storage %s failures",
    async (method) => {
      localStorage.setItem("unrelated", "value");
      vi.spyOn(api, "getJob").mockResolvedValue({
        ...snapshot,
        state: "running",
      });
      vi.spyOn(localStorage, method).mockImplementation(() => {
        throw new Error("Storage denied");
      });
      const hook = setup();
      act(() => hook.result.current.add(saved));
      await waitFor(() =>
        expect(hook.result.current.jobs[0].snapshot?.state).toBe("running"),
      );
      act(() => hook.result.current.dismiss("j"));
      expect(hook.result.current.jobs).toEqual([]);
    },
  );
  it("does not revive a dismissed job from a late poll or queued storage add", async () => {
    let resolve!: (job: MoveJob) => void;
    vi.spyOn(api, "getJob").mockImplementation(
      () =>
        new Promise((r) => {
          resolve = r;
        }),
    );
    const hook = setup();
    act(() => hook.result.current.add(saved));
    const key = jobsStorageKey("alice", "j");
    localStorage.removeItem(key);
    act(() =>
      window.dispatchEvent(
        new StorageEvent("storage", { key, newValue: null }),
      ),
    );
    await act(async () => resolve(snapshot));
    act(() =>
      window.dispatchEvent(
        new StorageEvent("storage", { key, newValue: JSON.stringify(saved) }),
      ),
    );
    expect(hook.result.current.jobs).toEqual([]);
    expect(localStorage.getItem(key)).toBeNull();
  });
  it("keeps dismissal after another tab has already read the job it will persist", async () => {
    const pending: ((job: MoveJob) => void)[] = [];
    vi.spyOn(api, "getJob").mockImplementation(
      () => new Promise((resolve) => pending.push(resolve)),
    );
    const first = setup();
    const second = setup();
    act(() => first.result.current.add(saved));
    const key = jobsStorageKey("alice", "j");
    act(() => window.dispatchEvent(new StorageEvent("storage", { key })));
    await waitFor(() => expect(pending).toHaveLength(2));
    const read = localStorage.getItem.bind(localStorage);
    let dismissed = false;
    vi.spyOn(localStorage, "getItem").mockImplementation((storageKey) => {
      const value = read(storageKey);
      if (storageKey === key && value !== null && !dismissed) {
        dismissed = true;
        second.result.current.dismiss("j");
      }
      return value;
    });
    await act(async () => pending[0](snapshot));
    expect(dismissed).toBe(true);
    act(() => window.dispatchEvent(new StorageEvent("storage", { key })));
    expect(first.result.current.jobs).toEqual([]);
    expect(second.result.current.jobs).toEqual([]);
    expect(localStorage.getItem(key)).toBeNull();

    // A stale writer may recreate the key even after a tombstone check.
    localStorage.setItem(key, JSON.stringify({ ...saved, notified: true }));
    act(() => window.dispatchEvent(new StorageEvent("storage", { key })));
    expect(first.result.current.jobs).toEqual([]);
    expect(second.result.current.jobs).toEqual([]);
    first.unmount();
    second.unmount();
    expect(setup().result.current.jobs).toEqual([]);
  });
  it("syncs a tombstone before the job removal event without affecting other jobs", () => {
    vi.spyOn(api, "getJob").mockImplementation(() => new Promise(() => {}));
    const first = setup();
    act(() => {
      first.result.current.add(saved);
      first.result.current.add({ ...saved, job_id: "other" });
    });
    const second = setup();
    act(() => second.result.current.dismiss("j"));
    const key = "as3m:move-dismissed:v1:alice:j";
    expect(localStorage.getItem(key)).not.toBeNull();
    act(() => window.dispatchEvent(new StorageEvent("storage", { key })));
    expect(first.result.current.jobs.map((job) => job.job_id)).toEqual([
      "other",
    ]);
    expect(second.result.current.jobs.map((job) => job.job_id)).toEqual([
      "other",
    ]);
  });
  it("does not restore dismissed v1 or v2 jobs or suppress the same id for another user", () => {
    vi.spyOn(api, "getJob").mockImplementation(() => new Promise(() => {}));
    const hook = setup();
    act(() => {
      hook.result.current.add(saved);
      hook.result.current.dismiss("j");
    });
    hook.unmount();
    localStorage.setItem(jobsStorageKey("alice", "j"), JSON.stringify(saved));
    localStorage.setItem(
      jobsStorageKey("alice"),
      JSON.stringify({
        version: 1,
        jobs: [saved, { ...saved, job_id: "other" }],
      }),
    );
    const restored = setup();
    expect(restored.result.current.jobs.map((job) => job.job_id)).toEqual([
      "other",
    ]);
    act(() => restored.result.current.add(saved));
    expect(restored.result.current.jobs.map((job) => job.job_id)).toEqual([
      "other",
    ]);
    restored.unmount();
    auth.username = "bob";
    const bob = setup();
    act(() => bob.result.current.add(saved));
    act(() =>
      window.dispatchEvent(
        new StorageEvent("storage", { key: "as3m:move-dismissed:v1:alice:j" }),
      ),
    );
    expect(bob.result.current.jobs.map((job) => job.job_id)).toEqual(["j"]);
  });
  it("retains tombstones for an hour and removes stale job keys before pruning them", () => {
    const now = 1_800_000_000_000;
    const clock = vi.spyOn(Date, "now").mockReturnValue(now);
    vi.spyOn(api, "getJob").mockImplementation(() => new Promise(() => {}));
    const hook = setup();
    act(() => {
      hook.result.current.add(saved);
      hook.result.current.dismiss("j");
    });
    hook.unmount();
    const key = jobsStorageKey("alice", "j");
    localStorage.setItem(key, JSON.stringify(saved));
    clock.mockReturnValue(now + 3_599_999);
    const beforeExpiry = setup();
    expect(beforeExpiry.result.current.jobs).toEqual([]);
    expect(
      localStorage.getItem("as3m:move-dismissed:v1:alice:j"),
    ).not.toBeNull();
    beforeExpiry.unmount();
    clock.mockReturnValue(now + 3_600_000);
    const afterExpiry = setup();
    expect(afterExpiry.result.current.jobs).toEqual([]);
    expect(localStorage.getItem(key)).toBeNull();
    expect(localStorage.getItem("as3m:move-dismissed:v1:alice:j")).toBeNull();
    act(() => afterExpiry.result.current.add(saved));
    expect(afterExpiry.result.current.jobs.map((job) => job.job_id)).toEqual([
      "j",
    ]);
  });
  it("bounds tombstones without evicting active dismissals and admits more after expiry", () => {
    const now = 1_800_000_000_000;
    const clock = vi.spyOn(Date, "now").mockReturnValue(now);
    vi.spyOn(api, "getJob").mockImplementation(() => new Promise(() => {}));
    const hook = setup();
    act(() => {
      for (let i = 0; i < 200; i++) {
        hook.result.current.add({ ...saved, job_id: `closed-${i}` });
        hook.result.current.dismiss(`closed-${i}`);
      }
      hook.result.current.add(saved);
      hook.result.current.dismiss("j");
    });
    expect(hook.result.current.jobs.map((job) => job.job_id)).toEqual(["j"]);
    expect(showToast).toHaveBeenCalledWith(
      expect.objectContaining({ title: "Dismiss limit reached" }),
    );
    expect(localStorage.length).toBe(201);
    localStorage.setItem(
      jobsStorageKey("alice", "closed-0"),
      JSON.stringify({ ...saved, job_id: "closed-0" }),
    );
    const restored = setup();
    expect(restored.result.current.jobs.map((job) => job.job_id)).toEqual([
      "j",
    ]);
    restored.unmount();
    clock.mockReturnValue(now + 3_600_000);
    act(() => hook.result.current.dismiss("j"));
    expect(hook.result.current.jobs).toEqual([]);
    expect(localStorage.length).toBe(1);
  });
  it("does not roll back a dismissal another tab accepted while the last slot fills", () => {
    vi.spyOn(api, "getJob").mockImplementation(() => new Promise(() => {}));
    const first = setup();
    act(() => {
      for (let i = 0; i < 199; i++) {
        first.result.current.add({ ...saved, job_id: `closed-${i}` });
        first.result.current.dismiss(`closed-${i}`);
      }
      first.result.current.add(saved);
    });
    const second = setup();
    act(() => second.result.current.add({ ...saved, job_id: "other" }));
    const write = localStorage.setItem.bind(localStorage);
    let interleaved = false;
    vi.spyOn(localStorage, "setItem").mockImplementation((key, value) => {
      if (key === "as3m:move-dismissed:v1:alice:j" && !interleaved) {
        interleaved = true;
        second.result.current.dismiss("other");
        write(key, value);
        second.result.current.dismiss("j");
      } else {
        write(key, value);
      }
    });
    act(() => first.result.current.dismiss("j"));
    expect(interleaved).toBe(true);
    const key = jobsStorageKey("alice", "j");
    localStorage.setItem(key, JSON.stringify(saved));
    act(() => window.dispatchEvent(new StorageEvent("storage", { key })));
    expect(first.result.current.jobs.map((job) => job.job_id)).not.toContain(
      "j",
    );
    expect(second.result.current.jobs.map((job) => job.job_id)).not.toContain(
      "j",
    );
  });
  it.each(["getItem", "setItem", "key", "removeItem"] as const)(
    "keeps dismissal usable in memory when tombstone storage %s throws",
    (method) => {
      vi.spyOn(api, "getJob").mockImplementation(() => new Promise(() => {}));
      const hook = setup();
      act(() => hook.result.current.add(saved));
      vi.spyOn(localStorage, method).mockImplementation(() => {
        throw new Error("Storage denied");
      });
      act(() => hook.result.current.dismiss("j"));
      expect(hook.result.current.jobs).toEqual([]);
    },
  );
  it("handles a denied localStorage getter during dismissal", () => {
    vi.spyOn(api, "getJob").mockImplementation(() => new Promise(() => {}));
    const hook = setup();
    act(() => hook.result.current.add(saved));
    const access = vi
      .spyOn(window, "localStorage", "get")
      .mockImplementation(() => {
        throw new Error("Storage denied");
      });
    try {
      act(() => hook.result.current.dismiss("j"));
      expect(hook.result.current.jobs).toEqual([]);
    } finally {
      access.mockRestore();
    }
  });
  it("does not show a stale record when storage removal fails", () => {
    vi.spyOn(api, "getJob").mockImplementation(() => new Promise(() => {}));
    const first = setup();
    act(() => first.result.current.add(saved));
    const second = setup();
    act(() => second.result.current.dismiss("j"));
    const key = jobsStorageKey("alice", "j");
    localStorage.setItem(key, JSON.stringify(saved));
    vi.spyOn(localStorage, "removeItem").mockImplementation(() => {
      throw new Error("Storage denied");
    });
    act(() => window.dispatchEvent(new StorageEvent("storage", { key })));
    expect(first.result.current.jobs).toEqual([]);
    expect(second.result.current.jobs).toEqual([]);
  });
  it("prunes interrupted admission reservations on reload", () => {
    const clock = vi.spyOn(Date, "now").mockReturnValue(1_800_000_000_000);
    const key = "as3m:move-dismiss-admission:v1:alice:interrupted";
    localStorage.setItem(key, "1800000000000");
    const beforeExpiry = setup();
    expect(localStorage.getItem(key)).not.toBeNull();
    beforeExpiry.unmount();
    clock.mockReturnValue(1_800_003_600_000);
    setup();
    expect(localStorage.getItem(key)).toBeNull();
  });
  it("ignores storage entries belonging to another user", () => {
    const hook = setup();
    const key = jobsStorageKey("bob", "j");
    localStorage.setItem(key, JSON.stringify(saved));
    act(() =>
      window.dispatchEvent(
        new StorageEvent("storage", { key, newValue: JSON.stringify(saved) }),
      ),
    );
    expect(hook.result.current.jobs).toEqual([]);
  });
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
  it("keeps a cached terminal result in the tray without a toast under StrictMode", async () => {
    localStorage.setItem(
      jobsStorageKey("alice"),
      JSON.stringify({ version: 1, jobs: [saved] }),
    );
    vi.spyOn(api, "getJob").mockResolvedValue(snapshot);
    const qc = new QueryClient();
    qc.setQueryData(["move-job", "alice", "j"], snapshot);
    const hook = renderHook(() => useMoveJobs(), {
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
    await waitFor(() =>
      expect(hook.result.current.jobs[0].snapshot?.state).toBe("done"),
    );
    expect(showToast).not.toHaveBeenCalled();
  });
  it.each([
    "done",
    "done_with_warnings",
    "failed_copy",
    "failed_delete",
    "cancelled_access",
  ] as const)("does not emit a notification for %s", async (state) => {
    const notify = vi.spyOn(notifications, "show");
    vi.spyOn(api, "getJob").mockResolvedValue({ ...snapshot, state });
    const hook = setup();
    act(() => hook.result.current.add(saved));
    await waitFor(() =>
      expect(hook.result.current.jobs[0].snapshot?.state).toBe(state),
    );
    expect(notify).not.toHaveBeenCalled();
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
    expect(localStorage.getItem(jobsStorageKey("alice", "j"))).toContain(
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
    expect(showToast).not.toHaveBeenCalled();
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
    expect(localStorage.getItem(jobsStorageKey("alice", "j"))).toContain(
      '"job_id":"j"',
    );
    expect(localStorage.getItem(jobsStorageKey("bob", "j"))).toBeNull();
  });
});
