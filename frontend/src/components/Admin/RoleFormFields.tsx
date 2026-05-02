import { TextInput } from "@mantine/core";
import type { UseFormReturnType } from "@mantine/form";
import type { AppRole } from "@/types/api";

interface Props {
  form: UseFormReturnType<AppRole>;
  disabled?: boolean;
  mode: "create" | "edit";
  /** When true, parent (wizard) is rendering name+type elsewhere — hide them here. */
  hideNameAndType?: boolean;
}

/**
 * STUB version (Task 6). Full implementation with type-conditional fields lands
 * in Task 7. For now renders only the `name` field so RoleEditPage compiles
 * end-to-end and admins can at least rename existing roles or fix typos.
 */
export function RoleFormFields({ form, disabled, mode, hideNameAndType }: Props) {
  if (hideNameAndType) return null; // wizard step 2 hides name; nothing else to render in stub
  return (
    <TextInput
      label="Name"
      required
      disabled={disabled || mode === "edit"}
      description={mode === "edit" ? "Cannot be changed after creation." : undefined}
      {...form.getInputProps("name")}
    />
  );
}
