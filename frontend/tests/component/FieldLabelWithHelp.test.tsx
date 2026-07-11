import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MantineProvider, Switch } from "@mantine/core";
import { FieldLabelWithHelp } from "@/components/FieldLabelWithHelp/FieldLabelWithHelp";

function renderLabel() {
  return render(
    <MantineProvider>
      <FieldLabelWithHelp
        label="Max client load"
        help="Objects loaded into the browser before 'Load more' appears. Larger folders paginate on the server beyond this. Default 10000."
      />
    </MantineProvider>,
  );
}

describe("FieldLabelWithHelp", () => {
  it("renders the label text and an info chip button", () => {
    renderLabel();
    expect(screen.getByText("Max client load")).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: /more about max client load/i }),
    ).toBeInTheDocument();
  });

  it("does not show the help text until the chip is clicked", () => {
    renderLabel();
    expect(
      screen.queryByText(/larger folders paginate on the server/i),
    ).not.toBeInTheDocument();
  });

  it("opens a popover with the full help text on click", async () => {
    renderLabel();
    await userEvent.click(
      screen.getByRole("button", { name: /more about max client load/i }),
    );
    expect(
      await screen.findByText(/larger folders paginate on the server/i),
    ).toBeInTheDocument();
  });

  it("is keyboard-accessible: Enter opens the popover once the chip is focused", async () => {
    renderLabel();
    const chip = screen.getByRole("button", {
      name: /more about max client load/i,
    });
    chip.focus();
    expect(chip).toHaveFocus();
    await userEvent.keyboard("{Enter}");
    expect(
      await screen.findByText(/larger folders paginate on the server/i),
    ).toBeInTheDocument();
  });

  it("does not toggle a Switch when its info chip is clicked", async () => {
    render(
      <MantineProvider>
        <Switch
          label={
            <FieldLabelWithHelp
              label="Disable deletion"
              help="When on, S3 file/folder delete operations return 403 server-side."
            />
          }
        />
      </MantineProvider>,
    );
    const toggle = screen.getByRole("switch", { name: /disable deletion/i });
    expect(toggle).not.toBeChecked();

    await userEvent.click(
      screen.getByRole("button", { name: /more about disable deletion/i }),
    );

    // The popover opened...
    expect(
      await screen.findByText(/return 403 server-side/i),
    ).toBeInTheDocument();
    // ...but the switch itself must still be unchecked — the chip click must
    // not bubble into the Switch's native <label for=...> click-forwarding.
    expect(toggle).not.toBeChecked();
  });
});
