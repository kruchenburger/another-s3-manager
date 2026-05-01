import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";
import { MantineProvider } from "@mantine/core";
import { MemoryRouter } from "react-router-dom";
import { ForbiddenPage } from "@/pages/ForbiddenPage";

function renderForbidden() {
  return render(
    <MantineProvider>
      <MemoryRouter>
        <ForbiddenPage />
      </MemoryRouter>
    </MantineProvider>,
  );
}

describe("ForbiddenPage", () => {
  it("renders the Forbidden title", () => {
    renderForbidden();
    expect(screen.getByText("Forbidden")).toBeInTheDocument();
  });

  it("renders explanatory body text", () => {
    renderForbidden();
    expect(screen.getByText(/don't have permission/i)).toBeInTheDocument();
  });

  it("renders a back-to-home link pointing to /", () => {
    renderForbidden();
    const link = screen.getByRole("link", { name: /back to home/i });
    expect(link).toHaveAttribute("href", "/");
  });

  it("renders the burger logo with accessible label", () => {
    renderForbidden();
    expect(screen.getByLabelText("Another S3 Manager")).toBeInTheDocument();
  });
});
