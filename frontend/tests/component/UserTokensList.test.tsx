import { describe, it, expect, vi } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { MantineProvider } from "@mantine/core";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";

import { UserTokensList } from "@/components/Admin/UserTokensList";
import * as tokensApi from "@/features/tokens/api/tokensApi";
import type { ApiTokenWithOwner } from "@/types/api";

function makeToken(
  overrides: Partial<ApiTokenWithOwner>,
): ApiTokenWithOwner {
  return {
    id: 1,
    name: "tok",
    is_read_only: true,
    max_read_bytes: 1024,
    created_at: "2026-01-01T00:00:00Z",
    last_used_at: null,
    revoked_at: null,
    owner_username: "alice",
    ...overrides,
  };
}

function renderList(props: { username: string; userId: number }) {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  return render(
    <QueryClientProvider client={client}>
      <MantineProvider>
        <UserTokensList {...props} />
      </MantineProvider>
    </QueryClientProvider>,
  );
}

describe("UserTokensList", () => {
  it("renders empty state when user has no tokens", async () => {
    vi.spyOn(tokensApi, "fetchAdminTokens").mockResolvedValue({ tokens: [] });
    renderList({ username: "alice", userId: 1 });
    await waitFor(() =>
      expect(screen.getByText(/no tokens issued yet/i)).toBeInTheDocument(),
    );
  });

  it("filters tokens by username", async () => {
    vi.spyOn(tokensApi, "fetchAdminTokens").mockResolvedValue({
      tokens: [
        makeToken({ id: 1, name: "alice-token", owner_username: "alice" }),
        makeToken({ id: 2, name: "bob-token", owner_username: "bob" }),
      ],
    });

    renderList({ username: "alice", userId: 1 });
    await waitFor(() =>
      expect(screen.getByText("alice-token")).toBeInTheDocument(),
    );
    expect(screen.queryByText("bob-token")).not.toBeInTheDocument();
  });

  it("opens CreateTokenModal preselected to this user when 'Issue token on behalf' is clicked", async () => {
    vi.spyOn(tokensApi, "fetchAdminTokens").mockResolvedValue({ tokens: [] });
    renderList({ username: "alice", userId: 1 });

    await waitFor(() =>
      expect(
        screen.getByRole("button", { name: /issue token on behalf/i }),
      ).toBeInTheDocument(),
    );
    fireEvent.click(
      screen.getByRole("button", { name: /issue token on behalf/i }),
    );
    // CreateTokenModal title is "Create MCP token" (after Phase 6a-1 rename)
    expect(screen.getByText(/create mcp token/i)).toBeInTheDocument();
  });

  it("renders the footer note pointing users to self-serve", async () => {
    vi.spyOn(tokensApi, "fetchAdminTokens").mockResolvedValue({ tokens: [] });
    renderList({ username: "alice", userId: 1 });
    await waitFor(() =>
      expect(
        screen.getByText(
          /user can also manage their own tokens at \/v2\/api-tokens/i,
        ),
      ).toBeInTheDocument(),
    );
  });
});
