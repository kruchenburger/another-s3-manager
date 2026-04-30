import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { apiRequest } from "@/hooks/useApiClient";
import { setCsrfToken, clearCsrfToken } from "@/utils/csrf";
import { ApiError } from "@/utils/apiError";

describe("apiRequest", () => {
  const fetchMock = vi.fn();

  beforeEach(() => {
    vi.stubGlobal("fetch", fetchMock);
    fetchMock.mockReset();
    clearCsrfToken();
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("includes credentials and JSON Accept header on GET", async () => {
    fetchMock.mockResolvedValue(
      new Response(JSON.stringify({ ok: true }), {
        status: 200,
        headers: { "content-type": "application/json" },
      }),
    );

    await apiRequest("/api/me");

    expect(fetchMock).toHaveBeenCalledWith(
      "/api/me",
      expect.objectContaining({
        credentials: "include",
        method: "GET",
        headers: expect.objectContaining({ Accept: "application/json" }),
      }),
    );
  });

  it("attaches X-CSRF-Token on mutating methods when token is set", async () => {
    setCsrfToken("csrf-123");
    fetchMock.mockResolvedValue(new Response("{}", { status: 200, headers: { "content-type": "application/json" } }));

    await apiRequest("/api/admin/users", { method: "POST", body: new FormData() });

    const callArgs = fetchMock.mock.calls[0][1] as RequestInit;
    expect((callArgs.headers as Record<string, string>)["X-CSRF-Token"]).toBe("csrf-123");
  });

  it("throws ApiError on non-2xx with parsed JSON body", async () => {
    fetchMock.mockResolvedValue(
      new Response(JSON.stringify({ detail: "Bad creds" }), {
        status: 401,
        headers: { "content-type": "application/json" },
      }),
    );

    await expect(apiRequest("/api/me")).rejects.toMatchObject({
      status: 401,
      body: { detail: "Bad creds" },
    });
    await expect(apiRequest("/api/me")).rejects.toBeInstanceOf(ApiError);
  });

  it("returns parsed JSON on 200", async () => {
    fetchMock.mockResolvedValue(
      new Response(JSON.stringify({ username: "alice" }), {
        status: 200,
        headers: { "content-type": "application/json" },
      }),
    );

    const data = await apiRequest<{ username: string }>("/api/me");
    expect(data).toEqual({ username: "alice" });
  });
});
