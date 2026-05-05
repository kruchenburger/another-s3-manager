import { describe, expect, it, vi } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { MantineProvider } from "@mantine/core";

import { EditTokenModal } from "@/components/Tokens/EditTokenModal";
import type { ApiToken } from "@/types/api";

const TOKEN: ApiToken = {
  id: 1,
  name: "ci-token",
  created_at: "2026-01-01T00:00:00Z",
  last_used_at: null,
  revoked_at: null,
  is_read_only: true,
  max_read_bytes: 2 * 1024 * 1024, // 2 MB
};

function renderModal(
  props: Partial<Parameters<typeof EditTokenModal>[0]> = {},
) {
  return render(
    <MantineProvider>
      <EditTokenModal
        opened
        onClose={() => {}}
        onSubmit={() => {}}
        loading={false}
        token={TOKEN}
        {...props}
      />
    </MantineProvider>,
  );
}

describe("EditTokenModal", () => {
  it("pre-fills name, read-only flag and MB size from the token", () => {
    renderModal();
    expect(screen.getByLabelText(/name/i)).toHaveValue("ci-token");
    expect(screen.getByLabelText(/read-only/i)).toBeChecked();
    // Mantine NumberInput renders the value as a string in the input field;
    // we assert the displayed value rather than the raw value.
    expect(screen.getByLabelText(/max read \(mb\)/i)).toHaveValue("2");
  });

  it("submits payload with bytes computed from MB", async () => {
    const onSubmit = vi.fn();
    renderModal({ onSubmit });

    fireEvent.change(screen.getByLabelText(/name/i), {
      target: { value: "renamed" },
    });
    fireEvent.change(screen.getByLabelText(/max read \(mb\)/i), {
      target: { value: "5" },
    });
    fireEvent.submit(document.querySelector("form")!);

    await waitFor(() => {
      expect(onSubmit).toHaveBeenCalledWith({
        name: "renamed",
        is_read_only: true,
        max_read_bytes: 5 * 1024 * 1024,
      });
    });
  });

  it("clamps MB above the 10 MB ceiling", async () => {
    const onSubmit = vi.fn();
    renderModal({ onSubmit });

    fireEvent.change(screen.getByLabelText(/max read \(mb\)/i), {
      target: { value: "999" },
    });
    fireEvent.submit(document.querySelector("form")!);

    await waitFor(() => {
      expect(onSubmit).toHaveBeenCalledWith(
        expect.objectContaining({ max_read_bytes: 10 * 1024 * 1024 }),
      );
    });
  });

  it("requires a non-empty name", async () => {
    const onSubmit = vi.fn();
    renderModal({ onSubmit });

    fireEvent.change(screen.getByLabelText(/name/i), { target: { value: "" } });
    fireEvent.submit(document.querySelector("form")!);

    expect(onSubmit).not.toHaveBeenCalled();
    await waitFor(() =>
      expect(screen.getByText(/name is required/i)).toBeInTheDocument(),
    );
  });
});
