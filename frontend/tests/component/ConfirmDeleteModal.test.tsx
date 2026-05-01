import { describe, expect, it, vi } from "vitest";
import { render, screen, fireEvent } from "@testing-library/react";
import { MantineProvider } from "@mantine/core";
import { ConfirmDeleteModal } from "@/components/Confirm/ConfirmDeleteModal";

function renderModal(props: Partial<Parameters<typeof ConfirmDeleteModal>[0]>) {
  const allProps = {
    opened: true,
    onClose: vi.fn(),
    onConfirm: vi.fn(),
    items: ["foo.txt"],
    ...props,
  };
  return {
    ...render(<MantineProvider><ConfirmDeleteModal {...allProps} /></MantineProvider>),
    props: allProps,
  };
}

describe("ConfirmDeleteModal", () => {
  it("renders single-item message", () => {
    renderModal({ items: ["foo.txt"] });
    expect(screen.getByText("foo.txt")).toBeInTheDocument();
  });

  it("renders bulk message with item count", () => {
    renderModal({ items: ["a.txt", "b.txt", "c.txt"] });
    expect(screen.getByText(/Delete the following 3 items/)).toBeInTheDocument();
    expect(screen.getByText("a.txt")).toBeInTheDocument();
    expect(screen.getByText("b.txt")).toBeInTheDocument();
    expect(screen.getByText("c.txt")).toBeInTheDocument();
  });

  it("truncates list to 10 items with overflow note", () => {
    const items = Array.from({ length: 15 }, (_, i) => `file-${i}.txt`);
    renderModal({ items });
    expect(screen.getByText(/and 5 more/)).toBeInTheDocument();
  });

  it("calls onConfirm when Delete clicked", () => {
    const { props } = renderModal({});
    fireEvent.click(screen.getByRole("button", { name: "Delete" }));
    expect(props.onConfirm).toHaveBeenCalledTimes(1);
  });

  it("calls onClose when Cancel clicked", () => {
    const { props } = renderModal({});
    fireEvent.click(screen.getByRole("button", { name: "Cancel" }));
    expect(props.onClose).toHaveBeenCalledTimes(1);
  });
});
