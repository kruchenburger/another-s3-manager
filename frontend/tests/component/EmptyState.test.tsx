import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";
import { MantineProvider } from "@mantine/core";
import { MemoryRouter } from "react-router-dom";
import { EmptyState } from "@/components/EmptyState/EmptyState";

function renderWithProviders(ui: React.ReactNode) {
  return render(
    <MantineProvider>
      <MemoryRouter>{ui}</MemoryRouter>
    </MantineProvider>,
  );
}

describe("EmptyState", () => {
  it("renders title and description", () => {
    renderWithProviders(<EmptyState title="Nothing here" description="Try uploading a file" />);
    expect(screen.getByText("Nothing here")).toBeInTheDocument();
    expect(screen.getByText("Try uploading a file")).toBeInTheDocument();
  });

  it("renders without description", () => {
    renderWithProviders(<EmptyState title="Empty" />);
    expect(screen.getByText("Empty")).toBeInTheDocument();
  });

  it("renders CTA when provided", () => {
    renderWithProviders(<EmptyState title="Empty" cta={<button>Upload</button>} />);
    expect(screen.getByRole("button", { name: "Upload" })).toBeInTheDocument();
  });
});
