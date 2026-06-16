import { describe, it, expect } from "vitest";
import { render, screen, renderHook } from "@testing-library/react";
import { MantineProvider } from "@mantine/core";
import { useForm } from "@mantine/form";
import { RoleFormFields } from "@/components/Admin/RoleFormFields";
import type { AppRole } from "@/types/api";

function makeForm(initial: Partial<AppRole>) {
  // Hook must be invoked inside a renderHook so React state lives.
  const { result } = renderHook(() =>
    useForm<AppRole>({
      initialValues: {
        name: "",
        type: "default",
        use_ssl: true,
        verify_ssl: true,
        addressing_style: "auto",
        allowed_buckets: [],
        secret_access_key: "",
        ...initial,
      } as AppRole,
    }),
  );
  return result.current;
}

function renderFields(props: {
  initial?: Partial<AppRole>;
  step: "type" | "credentials" | "all";
  mode?: "create" | "edit";
  disabled?: boolean;
}) {
  const form = makeForm(props.initial ?? {});
  return render(
    <MantineProvider>
      <RoleFormFields
        form={form}
        step={props.step}
        mode={props.mode ?? "create"}
        disabled={props.disabled}
      />
    </MantineProvider>,
  );
}

describe("RoleFormFields", () => {
  describe('step="type"', () => {
    it("shows Name + Description + RoleTypePicker; hides credential fields", () => {
      renderFields({ step: "type" });
      expect(screen.getByLabelText(/^Name\s*\*?$/)).toBeInTheDocument();
      // Description is meta — moved here from Step 2 so it's filled once for any role type
      expect(screen.getByLabelText(/^description$/i)).toBeInTheDocument();
      expect(screen.getByText(/AWS credential chain/i)).toBeInTheDocument();
      expect(screen.queryByLabelText(/^access key id/i)).not.toBeInTheDocument();
      expect(screen.queryByLabelText(/^secret access key/i)).not.toBeInTheDocument();
      expect(screen.queryByLabelText(/^region/i)).not.toBeInTheDocument();
      expect(screen.queryByLabelText(/^endpoint url/i)).not.toBeInTheDocument();
      expect(screen.queryByLabelText(/^profile name/i)).not.toBeInTheDocument();
      expect(screen.queryByLabelText(/^role arn/i)).not.toBeInTheDocument();
    });
  });

  describe('step="credentials" with type=credentials', () => {
    it("shows credential + scope fields + RoleTypeSummary; hides Name and Description (meta is on Step 1)", () => {
      renderFields({ step: "credentials", initial: { type: "credentials" } });
      expect(screen.getByLabelText(/^access key id/i)).toBeInTheDocument();
      expect(screen.getByLabelText(/^secret access key/i)).toBeInTheDocument();
      // Autocomplete renders the input + dropdown options under the same label;
      // narrow to the input only.
      expect(screen.getByRole("combobox", { name: /^region/i })).toBeInTheDocument();
      expect(screen.getByText(/allowed buckets/i)).toBeInTheDocument();
      // RoleTypeSummary surfaces the picked type at the top of Step 2 so the
      // user doesn't have to remember it.
      expect(screen.getByText(/Static access key \+ secret/i)).toBeInTheDocument();
      expect(screen.getByText(/^selected$/i)).toBeInTheDocument();
      // Name + Description are meta — they live on Step 1, not Step 2
      expect(screen.queryByLabelText(/^name$/i)).not.toBeInTheDocument();
      expect(screen.queryByLabelText(/^description$/i)).not.toBeInTheDocument();
    });
  });

  describe('step="all" with type=s3_compatible', () => {
    it("shows everything: Name + RoleTypePicker + endpoint + SSL toggles + addressing style + creds + scope", () => {
      renderFields({ step: "all", initial: { type: "s3_compatible" } });
      expect(screen.getByLabelText(/^Name\s*\*?$/)).toBeInTheDocument();
      expect(screen.getByText(/AWS credential chain/i)).toBeInTheDocument();
      expect(screen.getByLabelText(/^endpoint url/i)).toBeInTheDocument();
      expect(screen.getByLabelText(/^use ssl/i)).toBeInTheDocument();
      expect(screen.getByLabelText(/^verify ssl/i)).toBeInTheDocument();
      expect(screen.getAllByLabelText(/^addressing style/i).length).toBeGreaterThan(0);
      expect(screen.getByLabelText(/^access key id/i)).toBeInTheDocument();
      expect(screen.getByLabelText(/^secret access key/i)).toBeInTheDocument();
      expect(screen.getByRole("combobox", { name: /^region/i })).toBeInTheDocument();
      expect(screen.getByText(/allowed buckets/i)).toBeInTheDocument();
      expect(screen.getByLabelText(/^description$/i)).toBeInTheDocument();
    });
  });

  describe("edit mode", () => {
    it("disables every radio in the RoleTypePicker (type cannot change in edit)", () => {
      renderFields({ step: "all", mode: "edit", initial: { type: "credentials" } });
      const radios = screen.getAllByRole("radio");
      expect(radios.length).toBe(5);
      radios.forEach((r) => expect(r).toBeDisabled());
    });

    it("disables Name input and shows the 'Cannot be changed' description in edit mode", () => {
      renderFields({ step: "all", mode: "edit", initial: { type: "default" } });
      expect(screen.getByLabelText(/^Name\s*\*?$/)).toBeDisabled();
      expect(screen.getByText(/cannot be changed after creation/i)).toBeInTheDocument();
    });

    it("makes the secret optional in edit mode (placeholder hints to leave empty)", () => {
      renderFields({ step: "credentials", mode: "edit", initial: { type: "credentials" } });
      const secret = screen.getByLabelText(/^secret access key/i) as HTMLInputElement;
      expect(secret.placeholder).toMatch(/leave empty to keep existing secret/i);
    });
  });
});
