import { describe, it, expect, vi, beforeEach } from "vitest";
import { renderHook, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import type { ReactNode } from "react";

import { useMe } from "@/features/auth/hooks/useMe";

vi.mock("@/features/auth/api/authApi", () => ({
  fetchMe: vi.fn(),
}));

vi.mock("@/utils/csrf", () => ({
  setCsrfToken: vi.fn(),
}));

import { fetchMe } from "@/features/auth/api/authApi";

function wrapper({ children }: { children: ReactNode }) {
  const qc = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  return <QueryClientProvider client={qc}>{children}</QueryClientProvider>;
}

describe("useMe", () => {
  beforeEach(() => vi.clearAllMocks());

  it("exposes disable_deletion=true from backend", async () => {
    vi.mocked(fetchMe).mockResolvedValueOnce({
      username: "alice",
      is_admin: false,
      csrf_token: "csrf",
      theme: "auto",
      allowed_roles: ["r1"],
      default_role: null,
      must_change_password: false,
      disable_deletion: true,
      app_name: "S3",
      app_version: "1.0.0",
    });
    const { result } = renderHook(() => useMe(), { wrapper });
    await waitFor(() => expect(result.current.isSuccess).toBe(true));
    expect(result.current.data?.disable_deletion).toBe(true);
  });

  it("exposes disable_deletion=false when backend reports false", async () => {
    vi.mocked(fetchMe).mockResolvedValueOnce({
      username: "alice",
      is_admin: false,
      csrf_token: "csrf",
      theme: "auto",
      allowed_roles: ["r1"],
      default_role: null,
      must_change_password: false,
      disable_deletion: false,
      app_name: "S3",
      app_version: "1.0.0",
    });
    const { result } = renderHook(() => useMe(), { wrapper });
    await waitFor(() => expect(result.current.isSuccess).toBe(true));
    expect(result.current.data?.disable_deletion).toBe(false);
  });
});
