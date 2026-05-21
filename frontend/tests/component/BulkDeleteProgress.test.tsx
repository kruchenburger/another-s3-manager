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
  it("shows 'Deleting N of M: <name>' headline with 1-based position", () => {
    // started=0 means the first item is in-flight — UI shows "Deleting 1 of N".
    renderProgress({ started: 0, total: 10, currentName: "backup.tar.gz" });
    expect(screen.getByText(/deleting 1 of 10/i)).toBeInTheDocument();
    expect(screen.getByText(/backup\.tar\.gz/)).toBeInTheDocument();
  });

  it("advances the headline as `started` increases", () => {
    renderProgress({ started: 3, total: 10, currentName: "x" });
    // started=3 → 4th item in flight → "Deleting 4 of 10"
    expect(screen.getByText(/deleting 4 of 10/i)).toBeInTheDocument();
  });

  it("renders a Mantine Progress bar at the right percentage", () => {
    renderProgress({ started: 3, total: 10, currentName: "x" });
    const progressbar = screen.getByRole("progressbar");
    // position = started+1 = 4, percent = round(4/10 * 100) = 40
    expect(progressbar).toHaveAttribute("aria-valuenow", "40");
  });

  it("clamps the position to total on the last item", () => {
    // started=9 → position = min(10, 10) = 10 → "Deleting 10 of 10"
    renderProgress({ started: 9, total: 10, currentName: "last.txt" });
    expect(screen.getByText(/deleting 10 of 10/i)).toBeInTheDocument();
    expect(screen.getByRole("progressbar")).toHaveAttribute(
      "aria-valuenow",
      "100",
    );
  });

  it("renders 0% when total is 0 (empty batch edge case)", () => {
    renderProgress({ started: 0, total: 0, currentName: null });
    expect(screen.getByRole("progressbar")).toHaveAttribute(
      "aria-valuenow",
      "0",
    );
  });

  it("clamps to 100% when started somehow exceeds total (defensive)", () => {
    renderProgress({ started: 12, total: 10, currentName: null });
    expect(screen.getByRole("progressbar")).toHaveAttribute(
      "aria-valuenow",
      "100",
    );
  });

  it("omits the ': <name>' suffix when currentName is null", () => {
    renderProgress({ started: 4, total: 10, currentName: null });
    expect(screen.getByText(/^deleting 5 of 10$/i)).toBeInTheDocument();
  });
});
