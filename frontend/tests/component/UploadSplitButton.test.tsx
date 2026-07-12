import { describe, it, expect, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MantineProvider } from "@mantine/core";
import { UploadSplitButton } from "@/components/FileBrowser/UploadSplitButton";

// This file's Menu-item lookups previously raced the 5000ms vitest default
// test timeout with an internal findByRole wait ALSO set to 5000ms — under
// full-suite parallel worker contention (many jsdom + React instances
// competing for CPU), the Mantine Menu's portal + transition can take longer
// than usual to actually mount the item, and the outer test timeout has zero
// headroom over the inner wait to absorb that. Raising the file's test
// timeout (not weakening any assertion — the item still must actually
// appear, and userEvent still drives real interactions) gives the
// findByRole waits below room to succeed under contention instead of
// racing a budget they were already colliding with.
vi.setConfig({ testTimeout: 15000 });

function renderBtn(
  props: Partial<React.ComponentProps<typeof UploadSplitButton>> = {},
) {
  const onUploadFiles = vi.fn();
  const onUploadFolder = vi.fn();
  render(
    <MantineProvider>
      <UploadSplitButton
        onUploadFiles={onUploadFiles}
        onUploadFolder={onUploadFolder}
        {...props}
      />
    </MantineProvider>,
  );
  return { onUploadFiles, onUploadFolder };
}

describe("UploadSplitButton", () => {
  it("calls onUploadFiles when the primary Upload button is clicked", async () => {
    const user = userEvent.setup();
    const { onUploadFiles } = renderBtn();
    await user.click(screen.getByRole("button", { name: "Upload" }));
    expect(onUploadFiles).toHaveBeenCalledTimes(1);
  });

  it("opens the menu and calls onUploadFolder from 'Upload folder'", async () => {
    const user = userEvent.setup();
    const { onUploadFolder } = renderBtn();
    await user.click(
      screen.getByRole("button", { name: /more upload options/i }),
    );
    await user.click(
      await screen.findByRole(
        "menuitem",
        { name: /upload folder/i },
        { timeout: 10000 },
      ),
    );
    expect(onUploadFolder).toHaveBeenCalledTimes(1);
  });

  it("calls onUploadFiles from the menu 'Upload files' item", async () => {
    const user = userEvent.setup();
    const { onUploadFiles } = renderBtn();
    await user.click(
      screen.getByRole("button", { name: /more upload options/i }),
    );
    await user.click(
      await screen.findByRole(
        "menuitem",
        { name: /upload files/i },
        { timeout: 10000 },
      ),
    );
    expect(onUploadFiles).toHaveBeenCalledTimes(1);
  });
});
