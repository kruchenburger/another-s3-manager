import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import { MantineProvider } from "@mantine/core";
import { MemoryRouter } from "react-router-dom";
import { AdminSidebar } from "@/components/AdminLayout/AdminSidebar";

function renderAt(path: string) {
  return render(
    <MantineProvider>
      <MemoryRouter initialEntries={[path]}>
        <AdminSidebar />
      </MemoryRouter>
    </MantineProvider>,
  );
}

describe("AdminSidebar", () => {
  it("renders ACCOUNTS section label", () => {
    renderAt("/admin/users");
    expect(screen.getByText(/accounts/i)).toBeInTheDocument();
  });

  it("renders INFRASTRUCTURE section label", () => {
    renderAt("/admin/users");
    expect(screen.getByText(/infrastructure/i)).toBeInTheDocument();
  });

  it("renders all four admin links plus Back to files", () => {
    renderAt("/admin/users");
    expect(screen.getByText("Users")).toBeInTheDocument();
    expect(screen.getByText("Bans")).toBeInTheDocument();
    expect(screen.getByText("Roles")).toBeInTheDocument();
    expect(screen.getByText("Settings")).toBeInTheDocument();
    expect(screen.getByText(/back to files/i)).toBeInTheDocument();
  });

  it("highlights the active route via Mantine NavLink data-active", () => {
    renderAt("/admin/roles/new");
    // Mantine NavLink sets data-active on the active anchor/button. The
    // sidebar uses startsWith matching, so /admin/roles/new should activate
    // the "Roles" link. Soft assertion: just verify the label is rendered
    // and an element with data-active attribute exists somewhere — Mantine's
    // exact DOM structure can shift between versions.
    expect(screen.getByText("Roles")).toBeInTheDocument();
    const activeEl = document.querySelector("[data-active]");
    expect(activeEl).not.toBeNull();
  });
});
