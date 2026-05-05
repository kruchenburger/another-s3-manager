import { describe, expect, it, vi } from "vitest";
import { render, screen, fireEvent } from "@testing-library/react";
import { MantineProvider } from "@mantine/core";

import { TokensTable } from "@/components/Tokens/TokensTable";
import type { ApiToken } from "@/types/api";

const TOKEN_FIXTURE: ApiToken = {
  id: 1,
  name: "ci-token",
  created_at: "2026-01-01T00:00:00Z",
  last_used_at: null,
  revoked_at: null,
  is_read_only: true,
  max_read_bytes: 2 * 1024 * 1024,
};

const REVOKED_TOKEN: ApiToken = {
  ...TOKEN_FIXTURE,
  id: 2,
  name: "revoked-tok",
  revoked_at: "2026-02-01T00:00:00Z",
};

function renderTable(props: Partial<Parameters<typeof TokensTable>[0]> = {}) {
  return render(
    <MantineProvider>
      <TokensTable
        tokens={[TOKEN_FIXTURE]}
        onRevoke={() => {}}
        {...props}
      />
    </MantineProvider>,
  );
}

describe("TokensTable", () => {
  it("renders an empty state when there are no tokens", () => {
    renderTable({ tokens: [] });
    expect(screen.getByText(/no tokens/i)).toBeInTheDocument();
  });

  it("renders the token name and a revoke button", () => {
    renderTable();
    expect(screen.getByText("ci-token")).toBeInTheDocument();
    expect(screen.getByLabelText(/revoke ci-token/i)).toBeInTheDocument();
  });

  it("does not render edit button when onEdit prop is omitted", () => {
    renderTable({ tokens: [TOKEN_FIXTURE], onRevoke: () => {} });
    expect(screen.queryByLabelText(/edit ci-token/i)).not.toBeInTheDocument();
  });

  it("renders edit button when onEdit prop is provided and calls it on click", () => {
    const onEdit = vi.fn();
    renderTable({ tokens: [TOKEN_FIXTURE], onEdit });
    fireEvent.click(screen.getByLabelText(/edit ci-token/i));
    expect(onEdit).toHaveBeenCalledWith(TOKEN_FIXTURE);
  });

  it("does not render edit or revoke buttons for revoked tokens", () => {
    const onEdit = vi.fn();
    renderTable({ tokens: [REVOKED_TOKEN], onEdit });
    expect(screen.queryByLabelText(/edit revoked-tok/i)).not.toBeInTheDocument();
    expect(screen.queryByLabelText(/revoke revoked-tok/i)).not.toBeInTheDocument();
  });
});
