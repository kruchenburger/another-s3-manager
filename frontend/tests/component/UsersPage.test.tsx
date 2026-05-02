import { beforeEach, describe, expect, it, vi } from "vitest";
import {
  fireEvent,
  render,
  screen,
  waitFor,
  within,
} from "@testing-library/react";
import { MantineProvider } from "@mantine/core";
import { Notifications } from "@mantine/notifications";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import { UsersPage } from "@/pages/admin/UsersPage";

// Mock the entire adminApi module — must include bans exports too so that
// other test files which import from the same module aren't broken at module
// graph level (vi.mock is hoisted per file, so each file's mock is isolated,
// but listing all exports keeps this file's expectations explicit).
vi.mock("@/features/admin/api/adminApi", () => ({
  listBans: vi.fn(),
  unbanUser: vi.fn(),
  listUsers: vi.fn(),
  createUser: vi.fn(),
  updateUser: vi.fn(),
  deleteUser: vi.fn(),
  resetUserPassword: vi.fn(),
}));
import {
  createUser,
  deleteUser,
  listUsers,
  resetUserPassword,
  updateUser,
} from "@/features/admin/api/adminApi";

vi.mock("@/features/auth/hooks/useMe", () => ({
  useMe: vi.fn(),
}));
import { useMe } from "@/features/auth/hooks/useMe";

function mockMe(username: string) {
  vi.mocked(useMe).mockReturnValue({
    data: {
      username,
      is_admin: true,
      csrf_token: "x",
      theme: "auto",
      tour_seen_v1: true,
      allowed_roles: [],
      app_name: "x",
      app_version: "x",
    },
    isLoading: false,
  } as unknown as ReturnType<typeof useMe>);
}

function renderPage() {
  const qc = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
  return render(
    <QueryClientProvider client={qc}>
      <MantineProvider>
        <Notifications />
        <MemoryRouter>
          <UsersPage />
        </MemoryRouter>
      </MantineProvider>
    </QueryClientProvider>,
  );
}

const TWO_USERS = {
  users: [
    {
      username: "admin",
      is_admin: true,
      allowed_roles: [],
    },
    {
      username: "alice",
      is_admin: false,
      allowed_roles: ["dev", "ops"],
    },
  ],
  available_roles: ["dev", "ops", "qa"],
};

// Locate the row containing the per-row Edit button — the aria-label
// uniquely identifies the user, and the closest <tr> is that user's row.
async function findUserRow(username: string): Promise<HTMLElement> {
  const editBtn = await screen.findByRole("button", {
    name: `Edit ${username}`,
  });
  const row = editBtn.closest("tr");
  if (!row) throw new Error(`Row for ${username} not found`);
  return row as HTMLElement;
}

describe("UsersPage", () => {
  beforeEach(() => {
    vi.mocked(listUsers).mockReset();
    vi.mocked(createUser).mockReset();
    vi.mocked(updateUser).mockReset();
    vi.mocked(deleteUser).mockReset();
    vi.mocked(resetUserPassword).mockReset();
    vi.mocked(useMe).mockReset();
    mockMe("admin");
  });

  it("renders users in a table with admin badge only on the admin row and role badges on the regular row", async () => {
    vi.mocked(listUsers).mockResolvedValue(TWO_USERS);
    renderPage();

    const adminRow = await findUserRow("admin");
    const aliceRow = await findUserRow("alice");

    // Admin row: username cell text + an "admin" badge → both exist.
    // Use within(...).getAllByText to assert at least one node ("admin")
    // appears as a Badge (the one with class containing "Badge").
    const adminBadgesInAdminRow = within(adminRow).getAllByText(/^admin$/i);
    // The username cell + the badge = at least 2 nodes
    expect(adminBadgesInAdminRow.length).toBeGreaterThanOrEqual(2);

    // Alice row: no "admin" badge anywhere
    expect(within(aliceRow).queryByText(/^admin$/i)).not.toBeInTheDocument();

    // Alice has both role badges
    expect(within(aliceRow).getByText("dev")).toBeInTheDocument();
    expect(within(aliceRow).getByText("ops")).toBeInTheDocument();
  });

  it("disables Delete and Reset buttons for the current user's row (self-protect)", async () => {
    vi.mocked(listUsers).mockResolvedValue(TWO_USERS);
    renderPage();

    const selfDelete = await screen.findByRole("button", {
      name: "Delete admin",
    });
    const selfReset = await screen.findByRole("button", {
      name: "Reset password for admin",
    });
    expect(selfDelete).toBeDisabled();
    expect(selfReset).toBeDisabled();

    // Other users still have enabled buttons
    const aliceDelete = screen.getByRole("button", { name: "Delete alice" });
    const aliceReset = screen.getByRole("button", {
      name: "Reset password for alice",
    });
    expect(aliceDelete).not.toBeDisabled();
    expect(aliceReset).not.toBeDisabled();
  });

  it("deletes another user through the ConfirmDeleteModal", async () => {
    vi.mocked(listUsers).mockResolvedValue(TWO_USERS);
    vi.mocked(deleteUser).mockResolvedValue(undefined);
    renderPage();

    fireEvent.click(
      await screen.findByRole("button", { name: "Delete alice" }),
    );

    // Modal opens with alice's name
    await waitFor(() =>
      expect(screen.getByText(/confirm deletion/i)).toBeInTheDocument(),
    );
    const dialog = screen.getByRole("dialog");
    expect(dialog).toHaveTextContent("alice");

    // Click the "Delete" button inside the dialog
    fireEvent.click(within(dialog).getByRole("button", { name: /^delete$/i }));

    await waitFor(() => expect(deleteUser).toHaveBeenCalled());
    expect(vi.mocked(deleteUser).mock.calls[0]?.[0]).toBe("alice");
  });

  it("opens the Drawer in create mode with username + password fields when 'Add user' is clicked", async () => {
    vi.mocked(listUsers).mockResolvedValue(TWO_USERS);
    renderPage();

    // Wait for at least one row to render (proxy for query-loaded state)
    await screen.findByRole("button", { name: "Edit alice" });
    fireEvent.click(screen.getByRole("button", { name: /add user/i }));

    // Drawer title = "Create user"
    await screen.findByRole("dialog", { name: /create user/i });

    // Both Username and Password fields rendered + enabled (create mode).
    // Mantine appends " *" to required label text, so match flexibly.
    const username = screen.getByLabelText(/username/i) as HTMLInputElement;
    const password = screen.getByLabelText(/^password\s*\*?$/i) as HTMLInputElement;
    expect(username).toBeInTheDocument();
    expect(username).not.toBeDisabled();
    expect(password).toBeInTheDocument();
  });

  it("opens the Drawer in edit mode with disabled username and no password field", async () => {
    vi.mocked(listUsers).mockResolvedValue(TWO_USERS);
    renderPage();

    fireEvent.click(await screen.findByRole("button", { name: "Edit alice" }));

    // Drawer title includes "Edit user alice"
    await screen.findByRole("dialog", { name: /edit user alice/i });

    const username = screen.getByLabelText(/username/i) as HTMLInputElement;
    expect(username).toBeDisabled();
    expect(username.value).toBe("alice");

    // No password field in edit mode (matches "Password" or "Password *")
    expect(
      screen.queryByLabelText(/^password\s*\*?$/i),
    ).not.toBeInTheDocument();
  });

  it("disables the Administrator switch when editing self in the Drawer", async () => {
    vi.mocked(listUsers).mockResolvedValue(TWO_USERS);
    renderPage();

    fireEvent.click(await screen.findByRole("button", { name: "Edit admin" }));

    await screen.findByRole("dialog", { name: /edit user admin/i });

    const adminSwitch = screen.getByLabelText(
      /administrator/i,
    ) as HTMLInputElement;
    expect(adminSwitch).toBeDisabled();
  });

  it("renders a warning EmptyState when listUsers fails", async () => {
    vi.mocked(listUsers).mockRejectedValueOnce(new Error("boom"));
    renderPage();

    await waitFor(() =>
      expect(screen.getByText(/couldn't load users/i)).toBeInTheDocument(),
    );
    expect(screen.getByText(/boom/i)).toBeInTheDocument();
  });
});
