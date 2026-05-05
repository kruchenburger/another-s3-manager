import { describe, expect, it, vi } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { MantineProvider } from "@mantine/core";
import { CreateTokenModal } from "@/components/Tokens/CreateTokenModal";

function renderWith(props: Partial<Parameters<typeof CreateTokenModal>[0]> = {}) {
  return render(
    <MantineProvider>
      <CreateTokenModal
        opened
        onClose={() => {}}
        onSubmit={() => {}}
        loading={false}
        used={0}
        limit={10}
        {...props}
      />
    </MantineProvider>,
  );
}

describe("CreateTokenModal", () => {
  it("requires a name", async () => {
    const onSubmit = vi.fn();
    renderWith({ onSubmit });
    // Submit the form directly to trigger Mantine's form.onSubmit validation
    const form = document.querySelector("form")!;
    fireEvent.submit(form);
    expect(onSubmit).not.toHaveBeenCalled();
    await waitFor(() => expect(screen.getByText(/name is required/i)).toBeInTheDocument());
  });

  it("disables Create when at slot limit", () => {
    renderWith({ used: 10, limit: 10 });
    expect(screen.getByText(/Token limit reached/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /create/i })).toBeDisabled();
  });

  it("converts MB to bytes on submit", async () => {
    const onSubmit = vi.fn();
    renderWith({ onSubmit });
    fireEvent.change(screen.getByLabelText(/name/i), { target: { value: "x" } });
    const form = document.querySelector("form")!;
    fireEvent.submit(form);
    await waitFor(() =>
      expect(onSubmit).toHaveBeenCalledWith(
        { name: "x", is_read_only: true, max_read_bytes: 1048576 },
        undefined,
      ),
    );
  });
});
