import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";
import { MantineProvider } from "@mantine/core";
import { MemoryRouter } from "react-router-dom";
import { FileBreadcrumbs } from "@/components/FileBrowser/FileBreadcrumbs";

function renderCrumbs(path: string) {
  return render(
    <MantineProvider>
      <MemoryRouter>
        <FileBreadcrumbs bucket="my-bucket" roleId="aws-prod" path={path} />
      </MemoryRouter>
    </MantineProvider>,
  );
}

describe("FileBreadcrumbs", () => {
  it("shows bucket name as the home crumb", () => {
    renderCrumbs("");
    expect(screen.getByText("my-bucket")).toBeInTheDocument();
  });

  it("renders folder crumbs at root", () => {
    renderCrumbs("foo/bar");
    expect(screen.getByText("foo")).toBeInTheDocument();
    expect(screen.getByText("bar")).toBeInTheDocument();
  });

  it("renders the last crumb as plain text (not link)", () => {
    renderCrumbs("foo/bar");
    const barElement = screen.getByText("bar");
    expect(barElement.tagName).not.toBe("A");
  });

  it("encodes special chars in URL", () => {
    renderCrumbs("logs/2026:04");
    const link = screen.getByText("logs").closest("a");
    expect(link).toHaveAttribute("href", "/r/aws-prod/b/my-bucket/p/logs");
  });
});
