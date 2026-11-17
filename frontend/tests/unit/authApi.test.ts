import { it, expect, vi } from "vitest";
import { oidcStartUrl, login, logout } from "@/features/auth/api/authApi";
import { apiRequest } from "@/hooks/useApiClient";

vi.mock("@/hooks/useApiClient", () => ({
  apiRequest: vi.fn().mockResolvedValue({}),
}));

it("owns local login, logout and server SSO start URL", async () => {
  await login("reader", "password");
  expect(apiRequest).toHaveBeenCalledWith(
    "/api/login",
    expect.objectContaining({ method: "POST", body: expect.any(FormData) }),
  );
  await logout();
  expect(apiRequest).toHaveBeenCalledWith("/api/logout", { method: "POST" });
  expect(oidcStartUrl("//evil.example")).toBe(
    "/api/auth/oidc/login?return_to=%2F",
  );
  expect(oidcStartUrl("/bucket?q=one")).toBe(
    "/api/auth/oidc/login?return_to=%2Fbucket%3Fq%3Done",
  );
});
