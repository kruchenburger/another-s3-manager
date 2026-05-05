import { describe, it, expect, vi, beforeEach } from "vitest";

vi.mock("@/hooks/useApiClient", () => ({
  apiRequest: vi.fn(),
}));

import { apiRequest } from "@/hooks/useApiClient";
import { getPresignedDownloadUrl } from "@/features/files/api/filesApi";

describe("getPresignedDownloadUrl", () => {
  beforeEach(() => vi.clearAllMocks());

  it("calls /api/buckets/{bucket}/presigned with role+path query params", async () => {
    vi.mocked(apiRequest).mockResolvedValueOnce({
      url: "https://signed.example/x",
      expires_at: "2026-05-05T12:00:00+00:00",
    });
    const result = await getPresignedDownloadUrl(
      "my-bucket",
      "RoleA",
      "folder/file.txt",
    );
    expect(result.url).toBe("https://signed.example/x");
    expect(result.expires_at).toBe("2026-05-05T12:00:00+00:00");
    expect(apiRequest).toHaveBeenCalledTimes(1);
    const url = vi.mocked(apiRequest).mock.calls[0][0] as string;
    expect(url).toMatch(/^\/api\/buckets\/my-bucket\/presigned\?/);
    expect(url).toContain("role=RoleA");
    expect(url).toContain("path=folder%2Ffile.txt");
  });

  it("URL-encodes bucket name with special characters", async () => {
    vi.mocked(apiRequest).mockResolvedValueOnce({
      url: "https://x",
      expires_at: "2026-05-05T12:00:00+00:00",
    });
    await getPresignedDownloadUrl("bucket name", "r", "x");
    const url = vi.mocked(apiRequest).mock.calls[0][0] as string;
    expect(url).toMatch(/^\/api\/buckets\/bucket(%20|\+)name\/presigned\?/);
  });
});
