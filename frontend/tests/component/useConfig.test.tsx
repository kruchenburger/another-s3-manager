import type { ReactNode } from "react";
import { renderHook, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { vi, describe, it, expect, beforeEach } from "vitest";

vi.mock("@/hooks/useApiClient", () => ({
  apiRequest: vi.fn(),
}));

import { apiRequest } from "@/hooks/useApiClient";
import { useConfig } from "@/hooks/useConfig";

const apiRequestMock = apiRequest as unknown as ReturnType<typeof vi.fn>;

function wrap() {
  const qc = new QueryClient({
    defaultOptions: { queries: { retry: false, gcTime: 0 } },
  });
  return ({ children }: { children: ReactNode }) => (
    <QueryClientProvider client={qc}>{children}</QueryClientProvider>
  );
}

describe("useConfig", () => {
  beforeEach(() => apiRequestMock.mockReset());

  it("fetches /api/config and returns the AppConfig payload", async () => {
    apiRequestMock.mockResolvedValueOnce({
      items_per_page: 200,
      enable_lazy_loading: true,
      max_file_size: 100 * 1024 * 1024,
      disable_deletion: false,
      roles: [],
    });

    const { result } = renderHook(() => useConfig(), { wrapper: wrap() });

    await waitFor(() => expect(result.current.isSuccess).toBe(true));
    expect(result.current.data?.items_per_page).toBe(200);
    expect(result.current.data?.enable_lazy_loading).toBe(true);
    expect(apiRequestMock).toHaveBeenCalledWith("/api/config");
  });
});
