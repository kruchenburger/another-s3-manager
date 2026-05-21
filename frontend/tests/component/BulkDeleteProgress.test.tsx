import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import { MantineProvider } from "@mantine/core";
import { BulkDeleteProgress } from "@/components/FileBrowser/BulkDeleteProgress";

function renderProgress(props: Parameters<typeof BulkDeleteProgress>[0]) {
  return render(
    <MantineProvider>
      <BulkDeleteProgress {...props} />
    </MantineProvider>,
  );
}

describe("BulkDeleteProgress", () => {
  it("shows 'Deleting X of N: <name>' progress text", () => {
    renderProgress({ completed: 3, total: 10, currentName: "backup.tar.gz" });
    expect(screen.getByText(/deleting 3 of 10/i)).toBeInTheDocument();
    expect(screen.getByText(/backup\.tar\.gz/)).toBeInTheDocument();
  });

  it("renders a Mantine Progress bar with the right percentage", () => {
    renderProgress({ completed: 3, total: 10, currentName: "x" });
    const progressbar = screen.getByRole("progressbar");
    expect(progressbar).toHaveAttribute("aria-valuenow", "30");
  });

  it("clamps to 100% when completed === total", () => {
    renderProgress({ completed: 10, total: 10, currentName: null });
    expect(screen.getByRole("progressbar")).toHaveAttribute("aria-valuenow", "100");
  });
});
