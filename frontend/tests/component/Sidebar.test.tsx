import { render, screen } from "@testing-library/react";
import { MantineProvider } from "@mantine/core";
import { MemoryRouter } from "react-router-dom";
import { describe, it, expect, vi } from "vitest";
import { Sidebar } from "@/components/Sidebar/Sidebar";

vi.mock("@/features/auth/hooks/useMe", () => ({
  useMe: () => ({ data: { allowed_roles: [] } }),
}));

function renderSidebar(collapsed: boolean) {
  return render(
    <MantineProvider>
      <MemoryRouter initialEntries={["/v2/"]} basename="/v2">
        <Sidebar collapsed={collapsed} onToggleCollapsed={vi.fn()} />
      </MemoryRouter>
    </MantineProvider>,
  );
}

describe("Sidebar footer", () => {
  it("never renders a help / tour button (tour lives in the header only)", () => {
    renderSidebar(false);
    expect(
      screen.queryByRole("button", { name: /open help tour/i }),
    ).not.toBeInTheDocument();
    renderSidebar(true);
    expect(
      screen.queryByRole("button", { name: /open help tour/i }),
    ).not.toBeInTheDocument();
  });

  it("renders the collapse toggle when expanded", () => {
    renderSidebar(false);
    expect(
      screen.getByRole("button", { name: /collapse sidebar/i }),
    ).toBeInTheDocument();
  });

  it("renders the expand toggle when collapsed", () => {
    renderSidebar(true);
    expect(
      screen.getByRole("button", { name: /expand sidebar/i }),
    ).toBeInTheDocument();
  });
});
