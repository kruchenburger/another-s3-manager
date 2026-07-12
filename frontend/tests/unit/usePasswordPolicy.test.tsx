import { describe, it, expect, vi } from "vitest";
import { renderHook, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { usePasswordPolicy } from "@/features/auth/hooks/usePasswordPolicy";

vi.mock("@/features/admin/api/adminApi", () => ({
  getConfig: vi.fn(),
}));

import { getConfig } from "@/features/admin/api/adminApi";

function wrapper({ children }: { children: React.ReactNode }) {
  const qc = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  return <QueryClientProvider client={qc}>{children}</QueryClientProvider>;
}

describe("usePasswordPolicy", () => {
  it("selects only the 5 policy fields from the config response", async () => {
    vi.mocked(getConfig).mockResolvedValueOnce({
      roles: [],
      enable_lazy_loading: true,
      max_file_size: 100 * 1024 * 1024,
      max_client_load: 10000,
      presigned_url_default_ttl: 3600,
      presigned_url_max_ttl: 604800,
      disable_deletion: false,
      password_min_length: 12,
      password_min_uppercase: 2,
      password_min_lowercase: 1,
      password_min_digits: 1,
      password_min_special: 0,
      mcp_enabled: true,
      mcp_disable_writes: false,
      mcp_text_extensions: [],
      mcp_global_max_read_bytes: 10 * 1024 * 1024,
      mcp_summary_max_keys: 50000,
      mcp_summary_prefix_scan_pages: 20,
      mcp_list_page_size: 1000,
      mcp_list_max_page_size: 10000,
    });
    const { result } = renderHook(() => usePasswordPolicy(), { wrapper });
    await waitFor(() => expect(result.current.isSuccess).toBe(true));
    expect(result.current.data).toEqual({
      password_min_length: 12,
      password_min_uppercase: 2,
      password_min_lowercase: 1,
      password_min_digits: 1,
      password_min_special: 0,
    });
  });

  it("propagates loading state while config is fetching", () => {
    vi.mocked(getConfig).mockImplementationOnce(() => new Promise(() => {}));
    const { result } = renderHook(() => usePasswordPolicy(), { wrapper });
    expect(result.current.isLoading).toBe(true);
    expect(result.current.data).toBeUndefined();
  });
});
