import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";
import { MantineProvider } from "@mantine/core";
import { MemoryRouter } from "react-router-dom";
import { QueryErrorState } from "@/components/QueryErrorState/QueryErrorState";
import { ApiError } from "@/utils/apiError";

function renderWithProviders(ui: React.ReactNode) {
  return render(
    <MantineProvider>
      <MemoryRouter>{ui}</MemoryRouter>
    </MantineProvider>,
  );
}

describe("QueryErrorState", () => {
  it("renders the title", () => {
    renderWithProviders(
      <QueryErrorState error={new Error("boom")} title="Couldn't load files" />,
    );
    expect(screen.getByText("Couldn't load files")).toBeInTheDocument();
  });

  it("renders the message extracted from the error", () => {
    const err = new ApiError(400, "Bad Request", {
      detail: { code: "InvalidRegion", message: "Region is invalid" },
    });
    renderWithProviders(<QueryErrorState error={err} title="Failed" />);
    expect(screen.getByText("Region is invalid")).toBeInTheDocument();
  });

  it("renders the CTA when provided", () => {
    renderWithProviders(
      <QueryErrorState
        error={new Error("x")}
        title="Failed"
        cta={<button>Retry</button>}
      />,
    );
    expect(screen.getByRole("button", { name: "Retry" })).toBeInTheDocument();
  });

  it("renders a fallback message for unknown errors", () => {
    renderWithProviders(<QueryErrorState error={null} title="Failed" />);
    expect(screen.getByText("Failed")).toBeInTheDocument();
    expect(screen.getByText(/unknown error/i)).toBeInTheDocument();
  });
});
