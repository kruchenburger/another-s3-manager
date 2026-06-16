import { describe, it, expect, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MantineProvider } from "@mantine/core";
import { TtlPopover } from "@/components/TtlPopover/TtlPopover";

function renderPopover(over: Partial<React.ComponentProps<typeof TtlPopover>> = {}) {
  const defaultOnConfirm = vi.fn();
  const defaultOnClose = vi.fn();
  // Merge defaults with overrides; resolve callbacks so tests can assert on defaults.
  const resolvedOnConfirm = over.onConfirm ?? defaultOnConfirm;
  const resolvedOnClose = over.onClose ?? defaultOnClose;
  const { onConfirm: _oc, onClose: _ocl, ...rest } = over;
  render(
    <MantineProvider>
      <TtlPopover
        opened
        defaultTtl={3600}
        maxTtl={604800}
        target={<button type="button">anchor</button>}
        {...rest}
        onConfirm={resolvedOnConfirm}
        onClose={resolvedOnClose}
      />
    </MantineProvider>,
  );
  return { onConfirm: defaultOnConfirm, onClose: defaultOnClose };
}

describe("TtlPopover", () => {
  it("renders the Valid for select and a Copy button when opened", () => {
    renderPopover();
    // Mantine 9 Select renders as role="combobox" with the label as its accessible name.
    expect(screen.getByRole("combobox", { name: /valid for/i })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /copy/i })).toBeInTheDocument();
  });

  it("confirms with the default TTL without changing the select", async () => {
    const { onConfirm } = renderPopover();
    await userEvent.click(screen.getByRole("button", { name: /copy/i }));
    expect(onConfirm).toHaveBeenCalledWith(3600);
  });

  it("does not offer presets above maxTtl", () => {
    renderPopover({ maxTtl: 3600 });
    // Mantine Select renders all options in the DOM as role="option" elements even
    // before the dropdown is interacted with (inside a hidden listbox). Query them
    // with hidden:true so we don't depend on click-to-open behavior in jsdom.
    const options = screen.getAllByRole("option", { hidden: true });
    const labels = options.map((el) => el.textContent?.trim());
    // 6 hours (21600s) exceeds maxTtl=3600 — must not be offered.
    expect(labels).not.toContain("6 hours");
    // 1 hour (3600s) ≤ maxTtl — must be available.
    expect(labels).toContain("1 hour");
  });
});
