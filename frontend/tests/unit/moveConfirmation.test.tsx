import { describe, expect, it, vi, afterEach } from "vitest";
import { cleanup, render, screen, fireEvent } from "@testing-library/react";
import { MantineProvider } from "@mantine/core";
import { ConfirmMoveModal } from "@/components/FileBrowser/ConfirmMoveModal";
afterEach(cleanup);
describe("move confirmation", () => {
  it("always shows preflight counts, copy/delete explanation and requires confirmation", () => {
    const confirm = vi.fn();
    render(
      <MantineProvider>
        <ConfirmMoveModal
          preflight={{
            objects: 101,
            bytes: 2048,
            largest: 20,
            conflicts: [],
            blocked_reason: null,
          }}
          onConfirm={confirm}
          onClose={vi.fn()}
        />
      </MantineProvider>,
    );
    expect(
      screen.getByText(/This moves 101 objects \(2.0 KB\)/),
    ).toHaveTextContent(
      "ASM copies each object to the new location and then deletes the original.",
    );
    expect(screen.getByText(/This can take a while/)).toBeInTheDocument();
    expect(confirm).not.toHaveBeenCalled();
    fireEvent.click(screen.getByRole("button", { name: "Start move" }));
    expect(confirm).toHaveBeenCalledOnce();
  });
  it("prevents a blocked preflight from starting", () => {
    render(
      <MantineProvider>
        <ConfirmMoveModal
          preflight={{
            objects: 1,
            bytes: 1,
            largest: 1,
            conflicts: [],
            blocked_reason: "Busy",
          }}
          onConfirm={vi.fn()}
          onClose={vi.fn()}
        />
      </MantineProvider>,
    );
    expect(screen.getByRole("button", { name: "Start move" })).toBeDisabled();
  });
});
