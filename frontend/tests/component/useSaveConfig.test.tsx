import { renderHook, act } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import type { ReactNode } from "react";
import { vi, describe, it, expect } from "vitest";

vi.mock("@/features/admin/api/adminApi", () => ({
  getConfig: vi.fn(),
  saveConfig: vi.fn().mockResolvedValue({}),
}));

import { useSaveConfig } from "@/features/admin/hooks/useAdminConfig";
import { configQueryKey } from "@/hooks/useConfig";
import { adminConfigQueryKey } from "@/features/admin/hooks/useAdminConfig";
import { meQueryKey } from "@/features/auth/hooks/useMe";
import { toWritableConfig } from "@/features/admin/api/configShape";
import type { AppConfig } from "@/types/api";

it("preserves stored auth and opaque OAuth while excluding runtime settings", () => {
  const config = {
    roles: [],
    auth: { local_login: "off", oidc: { session_max_minutes: 5 } },
    mcp_oauth: { future: ["opaque"] },
    auth_runtime: { issuer: "environment-derived" },
  } as unknown as AppConfig;
  const writable = toWritableConfig(config);
  expect(writable.auth).toEqual({
    local_login: "off",
    oidc: { session_max_minutes: 5 },
  });
  expect(writable.mcp_oauth).toEqual({ future: ["opaque"] });
  expect(writable).not.toHaveProperty("auth_runtime");
});

function wrap(qc: QueryClient) {
  return ({ children }: { children: ReactNode }) => (
    <QueryClientProvider client={qc}>{children}</QueryClientProvider>
  );
}

describe("useSaveConfig invalidation", () => {
  it("invalidates the public config, admin config, and me queries on save", async () => {
    const qc = new QueryClient();
    const spy = vi.spyOn(qc, "invalidateQueries");
    const { result } = renderHook(() => useSaveConfig(), { wrapper: wrap(qc) });

    await act(async () => {
      await result.current.mutateAsync({ roles: [] } as never);
    });

    const invalidatedKeys = spy.mock.calls.map((c) => c[0]?.queryKey);
    expect(invalidatedKeys).toContainEqual(configQueryKey);
    expect(invalidatedKeys).toContainEqual(adminConfigQueryKey);
    expect(invalidatedKeys).toContainEqual(meQueryKey);
  });
});
