import { it, expect, vi, afterEach } from "vitest";
import { QueryClient } from "@tanstack/react-query";
import { SessionIdentity } from "@/features/auth/hooks/useSessionIdentity";
import { fetchMe } from "@/features/auth/api/authApi";
import { getCsrfToken, setCsrfToken } from "@/utils/csrf";
import type { MeResponse } from "@/types/api";
import { deleteFile } from "@/features/files/api/filesApi";

afterEach(() => {
  vi.unstubAllGlobals();
  vi.mocked(fetchMe).mockReset();
});

const account = (name: string) =>
  ({
    username: name,
    session_identity: `opaque-${name}`,
    csrf_token: `csrf-${name}`,
  }) as MeResponse;

it("test_batch_stops_after_session_change", async () => {
  const client = new QueryClient();
  const coordinator = new SessionIdentity(client);
  await coordinator.accept(account("a"), coordinator.generation);
  const fetch = vi.fn(async () => {
    await coordinator.accept(account("b"), coordinator.generation);
    return new Response(null, { status: 204 });
  });
  vi.stubGlobal("fetch", fetch);
  const batch = coordinator.beginAction();
  const run = async () => {
    for (const path of ["a.txt", "b.txt"]) {
      batch.assertCurrent();
      await deleteFile("bucket", "role", path, batch.signal);
      batch.assertCurrent();
    }
  };
  await expect(run()).rejects.toThrow();
  expect(fetch).toHaveBeenCalledTimes(1);
  expect(batch.signal.aborted).toBe(true);
  expect(getCsrfToken()).toBe("csrf-b");
  client.clear();
});

it("test_session_change_aborts_inflight_request", async () => {
  const client = new QueryClient();
  const coordinator = new SessionIdentity(client);
  await coordinator.accept(account("a"), coordinator.generation);
  const batch = coordinator.beginAction();
  const fetch = vi.fn(
    (_url: string, options: RequestInit) =>
      new Promise<Response>((_resolve, reject) => {
        options.signal!.addEventListener("abort", () =>
          reject(new DOMException("Aborted", "AbortError")),
        );
      }),
  );
  vi.stubGlobal("fetch", fetch);
  const outcome = deleteFile("bucket", "role", "a.txt", batch.signal).catch(
    (e) => e,
  );
  vi.mocked(fetchMe).mockResolvedValueOnce(account("b"));
  const refreshing = coordinator.refresh();
  expect(() => coordinator.beginAction()).toThrow();
  expect(batch.signal.aborted).toBe(true);
  expect(await outcome).toMatchObject({ name: "AbortError" });
  await refreshing;
  expect(coordinator.beginAction().signal.aborted).toBe(false);
  client.clear();
});

it("test_blocked_session_cannot_start_batch", async () => {
  const coordinator = new SessionIdentity(new QueryClient());
  expect(() => coordinator.beginAction()).toThrow();
  await coordinator.accept(account("a"), coordinator.generation);
  const batch = coordinator.beginAction();
  coordinator.logout();
  expect(batch.signal.aborted).toBe(true);
  expect(() => coordinator.beginAction()).toThrow();
});

vi.mock("@/features/auth/api/authApi", () => ({ fetchMe: vi.fn() }));

it("test_replacement_cancels_stale_data_and_installs_csrf_before_actions", async () => {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  const coordinator = new SessionIdentity(client);
  client.setQueryData(["files"], ["account-a-private"]);
  setCsrfToken("old-csrf");
  let finish!: (value: MeResponse) => void;
  vi.mocked(fetchMe).mockImplementationOnce(
    () =>
      new Promise((resolve) => {
        finish = resolve;
      }),
  );
  const oldGeneration = coordinator.generation;
  const pending = coordinator.refresh(true);
  expect(coordinator.blocked).toBe(true);
  expect(getCsrfToken()).toBeNull();
  await vi.waitFor(() => expect(fetchMe).toHaveBeenCalled());
  finish({
    username: "account-b",
    session_identity: "opaque-b",
    csrf_token: "new-csrf",
  } as MeResponse);
  await pending;
  expect(coordinator.blocked).toBe(false);
  expect(getCsrfToken()).toBe("new-csrf");
  expect(client.getQueryData(["files"])).toBeUndefined();
  await expect(
    coordinator.accept(
      { username: "account-a", csrf_token: "old-csrf" } as MeResponse,
      oldGeneration,
    ),
  ).rejects.toThrow("Superseded");
  expect(getCsrfToken()).toBe("new-csrf");
  client.clear();
});

it("rechecks a signal arriving during an older authoritative request", async () => {
  vi.mocked(fetchMe).mockReset();
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  const coordinator = new SessionIdentity(client);
  let finish!: (value: MeResponse) => void;
  vi.mocked(fetchMe).mockImplementationOnce(
    () =>
      new Promise((resolve) => {
        finish = resolve;
      }),
  );
  vi.mocked(fetchMe).mockResolvedValueOnce({
    username: "b",
    session_identity: "b",
    csrf_token: "b-csrf",
  } as MeResponse);
  const pending = coordinator.refresh();
  await vi.waitFor(() => expect(fetchMe).toHaveBeenCalledTimes(1));
  void coordinator.refresh();
  finish({
    username: "a",
    session_identity: "a",
    csrf_token: "a-csrf",
  } as MeResponse);
  await pending;
  expect(fetchMe).toHaveBeenCalledTimes(2);
  expect(getCsrfToken()).toBe("b-csrf");
  expect(client.getQueryData(["auth", "me"])).toMatchObject({ username: "b" });
  expect(coordinator.blocked).toBe(false);
  client.clear();
});

it("rejects an old in-flight mutation result after session replacement", async () => {
  vi.mocked(fetchMe).mockReset();
  vi.mocked(fetchMe).mockResolvedValue({
    username: "b",
    session_identity: "b",
    csrf_token: "b-csrf",
  } as MeResponse);
  const client = new QueryClient();
  const coordinator = new SessionIdentity(client);
  let finish!: (value: string) => void;
  const mutation = client.getMutationCache().build(client, {
    mutationFn: () =>
      new Promise<string>((resolve) => {
        finish = resolve;
      }),
  });
  const outcome = mutation.execute(undefined).then(
    () => "accepted",
    () => "refused",
  );
  await vi.waitFor(() => expect(finish).toBeTypeOf("function"));
  await coordinator.refresh();
  finish("account-a-result");
  expect(await outcome).toBe("refused");
  expect(getCsrfToken()).toBe("b-csrf");
  client.clear();
});
