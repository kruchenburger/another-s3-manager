import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { updateMyToken, updateAdminToken } from "@/features/tokens/api/tokensApi";
import { setCsrfToken, clearCsrfToken } from "@/utils/csrf";

describe("updateMyToken", () => {
  const fetchMock = vi.fn();

  beforeEach(() => {
    vi.stubGlobal("fetch", fetchMock);
    fetchMock.mockReset();
    clearCsrfToken();
    // PUT is a mutating method; CSRF middleware on backend requires the header.
    setCsrfToken("csrf-token-for-test");
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("issues PUT to /api/me/tokens/{id} with JSON body", async () => {
    fetchMock.mockResolvedValue(
      new Response(JSON.stringify({ id: 42, name: "renamed" }), {
        status: 200,
        headers: { "content-type": "application/json" },
      }),
    );

    const result = await updateMyToken(42, { name: "renamed", is_read_only: false });

    expect(result).toEqual({ id: 42, name: "renamed" });
    expect(fetchMock).toHaveBeenCalledWith(
      "/api/me/tokens/42",
      expect.objectContaining({
        method: "PUT",
        body: JSON.stringify({ name: "renamed", is_read_only: false }),
        headers: expect.objectContaining({
          "Content-Type": "application/json",
          "X-CSRF-Token": "csrf-token-for-test",
        }),
      }),
    );
  });

  it("supports partial updates with only one field", async () => {
    fetchMock.mockResolvedValue(
      new Response(JSON.stringify({ id: 7, max_read_bytes: 4096 }), {
        status: 200,
        headers: { "content-type": "application/json" },
      }),
    );

    await updateMyToken(7, { max_read_bytes: 4096 });

    expect(fetchMock).toHaveBeenCalledWith(
      "/api/me/tokens/7",
      expect.objectContaining({
        method: "PUT",
        body: JSON.stringify({ max_read_bytes: 4096 }),
      }),
    );
  });
});

describe("updateAdminToken", () => {
  const fetchMock = vi.fn();

  beforeEach(() => {
    vi.stubGlobal("fetch", fetchMock);
    fetchMock.mockReset();
    clearCsrfToken();
    setCsrfToken("csrf-token-for-test");
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("issues PUT to /api/admin/tokens/{id} with JSON body", async () => {
    fetchMock.mockResolvedValue(
      new Response(
        JSON.stringify({ id: 99, name: "renamed", owner_username: "alice" }),
        { status: 200, headers: { "content-type": "application/json" } },
      ),
    );

    const result = await updateAdminToken(99, { max_read_bytes: 4096 });

    expect(result).toEqual({ id: 99, name: "renamed", owner_username: "alice" });
    expect(fetchMock).toHaveBeenCalledWith(
      "/api/admin/tokens/99",
      expect.objectContaining({
        method: "PUT",
        body: JSON.stringify({ max_read_bytes: 4096 }),
        headers: expect.objectContaining({
          "Content-Type": "application/json",
          "X-CSRF-Token": "csrf-token-for-test",
        }),
      }),
    );
  });
});
