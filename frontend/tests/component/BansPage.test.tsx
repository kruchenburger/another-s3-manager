import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor, fireEvent, within } from "@testing-library/react";
import { MantineProvider } from "@mantine/core";
import { Notifications } from "@mantine/notifications";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import { BansPage } from "@/pages/admin/BansPage";

vi.mock("@/features/admin/api/adminApi", () => ({
  listBans: vi.fn(),
  unbanUser: vi.fn(),
}));
import { listBans, unbanUser } from "@/features/admin/api/adminApi";

function renderPage() {
  const qc = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
  return render(
    <QueryClientProvider client={qc}>
      <MantineProvider>
        <Notifications />
        <MemoryRouter>
          <BansPage />
        </MemoryRouter>
      </MantineProvider>
    </QueryClientProvider>,
  );
}

describe("BansPage", () => {
  beforeEach(() => {
    vi.mocked(listBans).mockReset();
    vi.mocked(unbanUser).mockReset();
  });

  it("shows the table with username, reason, and a relative banned-until that is NOT 'just now' for a future timestamp", async () => {
    vi.mocked(listBans).mockResolvedValueOnce([
      {
        username: "alice",
        banned_until: Math.floor(Date.now() / 1000) + 3600,
        banned_at: Math.floor(Date.now() / 1000),
        reason: "Too many failed login attempts",
      },
    ]);
    renderPage();
    await waitFor(() => expect(screen.getByText("alice")).toBeInTheDocument());
    expect(screen.getByText(/Too many failed login attempts/)).toBeInTheDocument();
    // Relative-future formatter should produce something like "in 59 minutes" / "in 1 hour"
    // Critically, NOT "just now"
    expect(screen.queryByText(/just now/i)).not.toBeInTheDocument();
    expect(screen.getByText(/^in \d+ (minutes?|hours?|days?)$/)).toBeInTheDocument();
  });

  it("renders the EmptyState when no bans are active", async () => {
    vi.mocked(listBans).mockResolvedValueOnce([]);
    renderPage();
    await waitFor(() =>
      expect(screen.getByText(/no bans currently active/i)).toBeInTheDocument(),
    );
  });

  it("opens the unban modal with the correct username and confirms", async () => {
    // Use mockResolvedValue (not Once) so the post-mutation invalidate refetch
    // also returns valid data instead of undefined.
    vi.mocked(listBans).mockResolvedValue([
      {
        username: "alice",
        banned_until: Math.floor(Date.now() / 1000) + 3600,
        banned_at: 0,
        reason: "x",
      },
    ]);
    vi.mocked(unbanUser).mockResolvedValueOnce(undefined);

    renderPage();
    await waitFor(() => expect(screen.getByText("alice")).toBeInTheDocument());

    // Click the Unban button on the row
    fireEvent.click(screen.getByRole("button", { name: /^unban$/i }));

    // Modal opens with username
    await waitFor(() => expect(screen.getByText("Unban user")).toBeInTheDocument());
    const dialog = screen.getByRole("dialog");
    expect(dialog).toHaveTextContent("alice");

    // Confirm
    fireEvent.click(within(dialog).getByRole("button", { name: /^unban$/i }));
    // TanStack Query mutate() passes a second context arg; assert only the first
    await waitFor(() => expect(unbanUser).toHaveBeenCalled());
    expect(vi.mocked(unbanUser).mock.calls[0]?.[0]).toBe("alice");
  });

  it("renders an error EmptyState when the bans query fails", async () => {
    vi.mocked(listBans).mockRejectedValueOnce(new Error("Server error"));
    renderPage();
    await waitFor(() =>
      expect(screen.getByText(/couldn't load bans/i)).toBeInTheDocument(),
    );
  });
});
