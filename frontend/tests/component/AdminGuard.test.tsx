import { describe, it, expect, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import { MantineProvider } from "@mantine/core";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { AdminGuard } from "@/components/AdminLayout/AdminGuard";

vi.mock("@/features/auth/hooks/useMe", () => ({
  useMe: vi.fn(),
}));
import { useMe } from "@/features/auth/hooks/useMe";

function renderRouter() {
  const qc = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  return render(
    <QueryClientProvider client={qc}>
      <MantineProvider>
        <MemoryRouter initialEntries={["/admin/users"]}>
          <Routes>
            <Route element={<AdminGuard />}>
              <Route path="/admin/users" element={<div>admin content</div>} />
            </Route>
          </Routes>
        </MemoryRouter>
      </MantineProvider>
    </QueryClientProvider>,
  );
}

describe("AdminGuard", () => {
  it("renders nested route content for admin users", () => {
    vi.mocked(useMe).mockReturnValue({
      data: { username: "a", is_admin: true },
      isLoading: false,
    } as unknown as ReturnType<typeof useMe>);
    renderRouter();
    expect(screen.getByText("admin content")).toBeInTheDocument();
  });

  it("renders ForbiddenPage for non-admin users", () => {
    vi.mocked(useMe).mockReturnValue({
      data: { username: "u", is_admin: false },
      isLoading: false,
    } as unknown as ReturnType<typeof useMe>);
    renderRouter();
    expect(screen.queryByText("admin content")).not.toBeInTheDocument();
    // ForbiddenPage shows the "Forbidden" title — unique signature element.
    expect(screen.getByText("Forbidden")).toBeInTheDocument();
    // And the back-to-home link.
    expect(
      screen.getByRole("link", { name: /back to home/i }),
    ).toBeInTheDocument();
  });

  it("renders nothing while loading", () => {
    vi.mocked(useMe).mockReturnValue({
      data: undefined,
      isLoading: true,
    } as unknown as ReturnType<typeof useMe>);
    const { container } = renderRouter();
    expect(container.textContent).not.toContain("admin content");
    expect(container.textContent).not.toMatch(/forbidden/i);
  });
});
