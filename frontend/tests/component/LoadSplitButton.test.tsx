import { describe, it, expect, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MantineProvider } from "@mantine/core";
import { LoadSplitButton } from "@/components/FileBrowser/LoadSplitButton";

function renderBtn(
  props: Partial<React.ComponentProps<typeof LoadSplitButton>> = {},
) {
  const onLoadMore = vi.fn();
  const onLoadAll = vi.fn();
  render(
    <MantineProvider>
      <LoadSplitButton
        onLoadMore={onLoadMore}
        onLoadAll={onLoadAll}
        loading={false}
        {...props}
      />
    </MantineProvider>,
  );
  return { onLoadMore, onLoadAll };
}

describe("LoadSplitButton", () => {
  it("calls onLoadMore when the primary 'Load more' button is clicked", async () => {
    const user = userEvent.setup();
    const { onLoadMore } = renderBtn();
    await user.click(screen.getByRole("button", { name: "Load more" }));
    expect(onLoadMore).toHaveBeenCalledTimes(1);
  });

  it("opens the menu and calls onLoadAll from 'Load all'", async () => {
    const user = userEvent.setup();
    const { onLoadAll } = renderBtn();
    await user.click(
      screen.getByRole("button", { name: /more load options/i }),
    );
    await user.click(
      await screen.findByRole(
        "menuitem",
        { name: /load all/i },
        { timeout: 5000 },
      ),
    );
    expect(onLoadAll).toHaveBeenCalledTimes(1);
  });

  it("disables the primary and the chevron while loading (double-submit guard)", () => {
    renderBtn({ loading: true });
    expect(screen.getByRole("button", { name: "Load more" })).toBeDisabled();
    expect(
      screen.getByRole("button", { name: /more load options/i }),
    ).toBeDisabled();
    // The "Load all" Menu.Item also carries disabled={loading} (defense-in-depth,
    // see the component). It isn't asserted here: the chevron above is disabled
    // while loading, so the menu can't be opened to reach the item — the reachable
    // guards (primary + chevron) are what a user can actually hit.
  });

  it("collapses to a spinner + Stop button while a Load all drain runs", async () => {
    const user = userEvent.setup();
    const onStopLoadAll = vi.fn();
    render(
      <MantineProvider>
        <LoadSplitButton
          onLoadMore={vi.fn()}
          onLoadAll={vi.fn()}
          loading={false}
          loadingAll={true}
          onStopLoadAll={onStopLoadAll}
        />
      </MantineProvider>,
    );
    // Load more / chevron are gone; only the spinner + Stop remain.
    expect(screen.queryByRole("button", { name: "Load more" })).toBeNull();
    const stop = screen.getByRole("button", { name: /stop/i });
    await user.click(stop);
    expect(onStopLoadAll).toHaveBeenCalledTimes(1);
  });
});
