import { beforeEach, describe, expect, it, vi } from "vitest";
import {
  createFolder,
  movePreflight,
  startMove,
  getJob,
  cleanupJob,
} from "@/features/files/api/filesApi";
import { apiRequest } from "@/hooks/useApiClient";
vi.mock("@/hooks/useApiClient", () => ({ apiRequest: vi.fn() }));
beforeEach(() => vi.clearAllMocks());
describe("folder operations transport", () => {
  it("sends exact names and role with JSON bodies", async () => {
    await createFolder("b", "role +", "a/# +%😀");
    expect(apiRequest).toHaveBeenCalledWith(
      "/api/buckets/b/folders?role=role+%2B",
      expect.objectContaining({
        method: "POST",
        body: '{"path":"a/# +%😀"}',
        headers: { "Content-Type": "application/json" },
      }),
    );
    const move = {
      items: [{ path: "x", kind: "file" as const, new_name: "y" }],
      destination: "",
    };
    await movePreflight("b", "r", move);
    expect(apiRequest).toHaveBeenLastCalledWith(
      "/api/buckets/b/move/preflight?role=r",
      expect.objectContaining({ body: JSON.stringify(move) }),
    );
  });
  it("reuses the action UUID on a retry and paginates failures", async () => {
    const action = {
      items: [{ path: "x", kind: "folder" as const }],
      destination: "dest",
      operation_id: crypto.randomUUID(),
      plan_fingerprint: "a".repeat(64),
    };
    vi.mocked(apiRequest)
      .mockRejectedValueOnce(new TypeError("offline"))
      .mockResolvedValue({ job_id: "j" });
    await expect(startMove("b", "r", action)).rejects.toThrow("offline");
    await startMove("b", "r", action);
    expect(vi.mocked(apiRequest).mock.calls[0][1]?.body).toBe(
      vi.mocked(apiRequest).mock.calls[1][1]?.body,
    );
    await getJob("j", 100);
    expect(apiRequest).toHaveBeenLastCalledWith(
      "/api/jobs/j?failures_offset=100",
    );
    await cleanupJob("j");
    expect(apiRequest).toHaveBeenLastCalledWith("/api/jobs/j/cleanup", {
      method: "POST",
    });
  });
});
