import { describe, it, expect, vi } from "vitest";
import { render, screen, fireEvent } from "@testing-library/react";
import { MantineProvider } from "@mantine/core";
import { RoleTypePicker } from "@/components/Admin/RoleTypePicker";

function renderPicker(props?: Partial<React.ComponentProps<typeof RoleTypePicker>>) {
  const defaults = {
    value: "default" as const,
    onChange: vi.fn(),
    disabled: false,
  };
  return render(
    <MantineProvider>
      <RoleTypePicker {...defaults} {...props} />
    </MantineProvider>,
  );
}

describe("RoleTypePicker", () => {
  it("renders all 5 friendly labels", () => {
    renderPicker();
    expect(screen.getByText(/AWS credential chain/i)).toBeInTheDocument();
    expect(screen.getByText(/Named AWS profile/i)).toBeInTheDocument();
    expect(screen.getByText(/STS assume role/i)).toBeInTheDocument();
    expect(screen.getByText(/Static access key \+ secret/i)).toBeInTheDocument();
    expect(screen.getByText(/Other S3-compatible service/i)).toBeInTheDocument();
  });

  it("renders all 5 code suffixes via <Code>", () => {
    renderPicker();
    // Code element renders "default", "profile", "assume_role", "credentials", "s3_compatible"
    expect(screen.getByText("default")).toBeInTheDocument();
    expect(screen.getByText("profile")).toBeInTheDocument();
    expect(screen.getByText("assume_role")).toBeInTheDocument();
    expect(screen.getByText("credentials")).toBeInTheDocument();
    expect(screen.getByText("s3_compatible")).toBeInTheDocument();
  });

  it("fires onChange with the new code when a different option is selected", () => {
    const onChange = vi.fn();
    renderPicker({ onChange });
    // Mantine renders the 5 radios; click the credentials one by its label.
    // The <Radio>'s accessible name is the full custom label content; click the input directly.
    const radios = screen.getAllByRole("radio");
    expect(radios).toHaveLength(5);
    // Find the credentials radio (4th in DOM order per OPTIONS array)
    const credsRadio = radios[3];
    fireEvent.click(credsRadio);
    expect(onChange).toHaveBeenCalledWith("credentials");
  });

  it("disables every radio when disabled=true", () => {
    renderPicker({ disabled: true });
    const radios = screen.getAllByRole("radio");
    expect(radios).toHaveLength(5);
    radios.forEach((r) => expect(r).toBeDisabled());
  });

  it("exposes a tooltip-triggering info icon on the default option (with accessible name)", () => {
    renderPicker();
    // Mantine Tooltip is lazy-mounted in jsdom, so its inner anchors aren't
    // in the DOM until hover. We assert the trigger is present + has an
    // accessible name; the actual link URLs are covered by manual smoke and
    // by the source of truth (constant array). Triggering hover here would
    // require @testing-library/user-event + Mantine Tooltip portal handling
    // — overkill for verifying that we surfaced an info affordance.
    const infoIcon = screen.getByLabelText(
      /more details about AWS credential chain/i,
    );
    expect(infoIcon).toBeInTheDocument();
  });
});
