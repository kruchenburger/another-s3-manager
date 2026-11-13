import { describe, it, expect, vi } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { MantineProvider } from "@mantine/core";
import { UserDrawer } from "@/components/Admin/UserDrawer";

vi.mock("@/features/auth/hooks/usePasswordPolicy", () => ({
  usePasswordPolicy: () => ({ data: undefined, isError: true }),
}));
vi.mock("@/components/Admin/UserTokensList", () => ({ UserTokensList: () => null }));

function show(username = "alice", source: "local" | "oidc" = "oidc") {
  const submit = vi.fn();
  render(<MantineProvider env="test"><UserDrawer opened mode="edit" currentUsername="admin"
    availableRoles={["Default"]} onClose={() => {}} onSubmit={submit}
    initialUser={{ id: 2, username, is_admin: false, allowed_roles: ["Default"], missing_roles: [],
      auth_source: source, is_disabled: false }} /></MantineProvider>);
  return submit;
}

describe("UserDrawer lifecycle", () => {
  it("shows source and submits disable with existing grants", async () => {
    const submit = show();
    expect(screen.getByText("Sign-in source: SSO")).toBeInTheDocument();
    const toggle = screen.getByRole("switch", { name: /Disabled/ });
    fireEvent.click(toggle);
    fireEvent.click(screen.getByRole("button", { name: "Save changes" }));
    await waitFor(() => expect(submit).toHaveBeenCalledWith({ mode: "edit", username: "alice",
      is_admin: false, allowed_roles: ["Default"], is_disabled: true }));
  });
  it("keeps local source and self protection", () => {
    show("admin", "local");
    expect(screen.getByText("Sign-in source: Local")).toBeInTheDocument();
    expect(screen.getByRole("switch", { name: /Disabled/ })).toBeDisabled();
    expect(screen.getByRole("switch", { name: /Administrator/ })).toBeDisabled();
  });
});
