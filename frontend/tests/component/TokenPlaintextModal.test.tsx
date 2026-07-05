import { describe, expect, it, vi } from "vitest";
import { render, screen, fireEvent } from "@testing-library/react";
import { MantineProvider } from "@mantine/core";
import { TokenPlaintextModal } from "@/components/Tokens/TokenPlaintextModal";

describe("TokenPlaintextModal", () => {
  it("renders the plaintext token", () => {
    render(
      <MantineProvider>
        <TokenPlaintextModal opened onClose={() => {}} plaintext="as3m_test123" />
      </MantineProvider>,
    );
    // Token may appear in multiple DOM nodes (Code block renders in pre element)
    const elements = screen.getAllByText(/as3m_test123/);
    expect(elements.length).toBeGreaterThan(0);
  });

  it("does not close on Escape", () => {
    const onClose = vi.fn();
    render(
      <MantineProvider>
        <TokenPlaintextModal opened onClose={onClose} plaintext="as3m_x" />
      </MantineProvider>,
    );
    fireEvent.keyDown(document.body, { key: "Escape" });
    expect(onClose).not.toHaveBeenCalled();
  });

  it("toggles MCP snippet", () => {
    render(
      <MantineProvider>
        <TokenPlaintextModal opened onClose={() => {}} plaintext="as3m_x" />
      </MantineProvider>,
    );
    fireEvent.click(screen.getByRole("button", { name: /show mcp config/i }));
    expect(screen.getByText(/mcpServers/)).toBeInTheDocument();
  });
});
