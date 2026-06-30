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
    await user.click(await screen.findByRole("menuitem", { name: /load all/i }));
    expect(onLoadAll).toHaveBeenCalledTimes(1);
  });

  it("disables the primary and the chevron while loading (double-submit guard)", () => {
    renderBtn({ loading: true });
    expect(screen.getByRole("button", { name: "Load more" })).toBeDisabled();
    expect(
      screen.getByRole("button", { name: /more load options/i }),
    ).toBeDisabled();
  });
});
