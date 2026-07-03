import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { MantineProvider } from "@mantine/core";
import { describe, expect, it } from "vitest";
import { BucketPageHeader } from "@/components/FileBrowser/BucketPageHeader";
import { mutedSlateBlueTheme } from "@/app/theme";

function renderHeader(
  props: Partial<Parameters<typeof BucketPageHeader>[0]> = {},
) {
  return render(
    <MantineProvider theme={mutedSlateBlueTheme}>
      <MemoryRouter>
        <BucketPageHeader
          bucket="my-bucket"
          roleId="R2"
          objectCount={143}
          truncated={false}
          {...props}
        />
      </MemoryRouter>
    </MantineProvider>,
  );
}

describe("BucketPageHeader", () => {
  it("renders the bucket name as a level-2 heading", () => {
    renderHeader();
    expect(
      screen.getByRole("heading", { level: 2, name: "my-bucket" }),
    ).toBeInTheDocument();
  });

  it("renders the role badge and exact object count", () => {
    renderHeader();
    expect(screen.getByText("R2")).toBeInTheDocument();
    expect(screen.getByText("143 objects")).toBeInTheDocument();
  });

  it("renders N+ when the listing is truncated", () => {
    renderHeader({ objectCount: 50, truncated: true });
    expect(screen.getByText("50+ objects")).toBeInTheDocument();
  });

  it("pluralizes correctly for a single object", () => {
    renderHeader({ objectCount: 1 });
    expect(screen.getByText("1 object")).toBeInTheDocument();
  });
});
