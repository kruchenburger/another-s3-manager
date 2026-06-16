import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { MantineProvider } from "@mantine/core";
import { Notifications } from "@mantine/notifications";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { DefaultRolePicker } from "@/components/AppShell/DefaultRolePicker";

const useMeMock = vi.fn();
const mutateMock = vi.fn();

vi.mock("@/features/auth/hooks/useMe", () => ({
  useMe: () => useMeMock(),
  meQueryKey: ["auth", "me"],
}));
vi.mock("@/features/auth/hooks/useUpdateMyDefaultRole", () => ({
  useUpdateMyDefaultRole: () => ({ mutate: mutateMock, isPending: false }),
}));

function renderPicker() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <MantineProvider>
      <Notifications />
      <QueryClientProvider client={qc}>
        <DefaultRolePicker />
      </QueryClientProvider>
    </MantineProvider>,
  );
}

describe("DefaultRolePicker", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });
  afterEach(() => vi.restoreAllMocks());

  it("renders allowed_roles as options and highlights the current default", () => {
    useMeMock.mockReturnValue({
      data: { allowed_roles: ["RoleA", "RoleB", "RoleC"], default_role: "RoleB" },
    });
    renderPicker();
    // Mantine 9 Select renders the input with role="combobox" (ARIA-correct).
    const trigger = screen.getByRole("combobox");
    expect(trigger).toHaveValue("RoleB");
  });

  it("calls the update mutation with the selected role", async () => {
    useMeMock.mockReturnValue({
      data: { allowed_roles: ["RoleA", "RoleB"], default_role: "RoleA" },
    });
    renderPicker();
    const trigger = screen.getByRole("combobox");
    fireEvent.click(trigger);
    await waitFor(() => expect(screen.getByText("RoleB")).toBeInTheDocument());
    fireEvent.click(screen.getByText("RoleB"));
    await waitFor(() =>
      expect(mutateMock).toHaveBeenCalledWith("RoleB", expect.anything()),
    );
  });

  it("renders nothing when allowed_roles is empty", () => {
    useMeMock.mockReturnValue({
      data: { allowed_roles: [], default_role: null },
    });
    renderPicker();
    // No Select textbox should be rendered when there are no roles to pick.
    expect(screen.queryByRole("combobox")).toBeNull();
  });

  it("renders nothing when allowed_roles has only one entry (picker would be degenerate)", () => {
    useMeMock.mockReturnValue({
      data: { allowed_roles: ["Solo"], default_role: "Solo" },
    });
    renderPicker();
    // No Select textbox should be rendered when there's only one role.
    expect(screen.queryByRole("combobox")).toBeNull();
  });
});
