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
        <Sidebar
          collapsed={collapsed}
          onToggleCollapsed={vi.fn()}
          onOpenTour={vi.fn()}
        />
      </MemoryRouter>
    </MantineProvider>,
  );
}

describe("Sidebar footer", () => {
  it("hides the help button when collapsed", () => {
    renderSidebar(true);
    expect(
      screen.queryByRole("button", { name: /open help tour/i }),
    ).not.toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: /expand sidebar/i }),
    ).toBeInTheDocument();
  });

  it("shows the help button when expanded", () => {
    renderSidebar(false);
    expect(
      screen.getByRole("button", { name: /open help tour/i }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: /collapse sidebar/i }),
    ).toBeInTheDocument();
  });
});
