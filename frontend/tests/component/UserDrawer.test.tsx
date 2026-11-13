import { describe, it, expect, vi } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { MantineProvider } from "@mantine/core";
import { apiRequest } from "@/hooks/useApiClient";
import { updateUser } from "@/features/admin/api/adminApi";
import { UserDrawer } from "@/components/Admin/UserDrawer";

vi.mock("@/hooks/useApiClient", () => ({ apiRequest: vi.fn() }));

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


it.each([false, true])("omits untouched disabled state, including a toggle reverted to its initial value (%s)", async (revert) => {
  const submit = show();
  if (revert) {
    const toggle = screen.getByRole("switch", { name: /Disabled/ });
    fireEvent.click(toggle);
    fireEvent.click(toggle);
  }
  fireEvent.click(screen.getByRole("switch", { name: "Administrator" }));
  fireEvent.click(screen.getByRole("button", { name: "Save changes" }));
  await waitFor(() => expect(submit).toHaveBeenCalled());
  expect(submit.mock.calls[0][0]).toEqual({ mode: "edit", username: "alice", is_admin: true, allowed_roles: ["Default"] });
  expect(submit.mock.calls[0][0]).not.toHaveProperty("is_disabled");
});

it.each([undefined, false, true])("serializes disabled only when present (%s)", async (disabled) => {
  vi.mocked(apiRequest).mockClear();
  vi.mocked(apiRequest).mockResolvedValue(undefined);
  await updateUser("alice", { allowed_roles: ["Default"], ...(disabled === undefined ? {} : { is_disabled: disabled }) });
  const options = vi.mocked(apiRequest).mock.calls[0][1];
  const body = options?.body as FormData;
  expect(body.get("allowed_roles")).toBe("Default");
  expect(body.has("is_disabled")).toBe(disabled !== undefined);
  if (disabled !== undefined) expect(body.get("is_disabled")).toBe(String(disabled));
});

it("resets disabled edit intent when reopening for another user", async () => {
  const submit = vi.fn();
  const initial = { id: 2, username: "alice", is_admin: false, allowed_roles: [], missing_roles: [], auth_source: "local" as const, is_disabled: false };
  const draw = (opened: boolean, user = initial) => <MantineProvider env="test"><UserDrawer opened={opened} mode="edit" currentUsername="admin" availableRoles={[]} onClose={() => {}} onSubmit={submit} initialUser={user} /></MantineProvider>;
  const view = render(draw(true));
  fireEvent.click(screen.getByRole("switch", { name: /Disabled/ }));
  view.rerender(draw(false));
  view.rerender(draw(true, { ...initial, id: 3, username: "bob", is_disabled: true }));
  fireEvent.click(screen.getByRole("button", { name: "Save changes" }));
  await waitFor(() => expect(submit).toHaveBeenCalled());
  expect(submit.mock.calls[0][0]).not.toHaveProperty("is_disabled");
  expect(submit.mock.calls[0][0].username).toBe("bob");
});
