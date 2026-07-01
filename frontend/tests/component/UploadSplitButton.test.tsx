import { describe, it, expect, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MantineProvider } from "@mantine/core";
import { UploadSplitButton } from "@/components/FileBrowser/UploadSplitButton";

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
        { timeout: 5000 },
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
        { timeout: 5000 },
      ),
    );
    expect(onUploadFiles).toHaveBeenCalledTimes(1);
  });
});
