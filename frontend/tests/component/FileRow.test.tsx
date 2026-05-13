import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen, fireEvent } from "@testing-library/react";
import { MantineProvider, Table } from "@mantine/core";
import { MemoryRouter } from "react-router-dom";
import { FileRow } from "@/components/FileBrowser/FileRow";
import type { FileEntry } from "@/types/api";

vi.mock("@/features/auth/hooks/useMe", () => ({
  useMe: vi.fn(),
}));

import { useMe } from "@/features/auth/hooks/useMe";

beforeEach(() => {
  // Default: deletion enabled. Individual tests can override before render.
  vi.mocked(useMe).mockReturnValue({
    data: { disable_deletion: false },
  } as never);
});

type RowCallbacks = Partial<{
  onToggleSelect: (name: string) => void;
  onNavigate: (name: string) => void;
  onDownload: (name: string) => void;
  onCopyUrl: (name: string) => void;
  onPreview: (name: string) => void;
  onDelete: (name: string) => void;
}>;

function renderRow(file: FileEntry, callbacks: RowCallbacks = {}) {
  const props = {
    file,
    index: 0,
    selected: false,
    onToggleSelect: vi.fn(),
    onNavigate: vi.fn(),
    onDownload: vi.fn(),
    onCopyUrl: vi.fn(),
    onPreview: vi.fn(),
    onDelete: vi.fn(),
    ...callbacks,
  };
  return {
    ...render(
      <MantineProvider>
        <MemoryRouter>
          <Table>
            <Table.Tbody>
              <FileRow {...props} />
            </Table.Tbody>
          </Table>
        </MemoryRouter>
      </MantineProvider>,
    ),
    props,
  };
}

describe("FileRow", () => {
  it("renders file with size and date", () => {
    renderRow({
      name: "report.pdf",
      is_directory: false,
      size: 2048,
      last_modified: new Date().toISOString(),
    });
    expect(screen.getByText("report.pdf")).toBeInTheDocument();
    expect(screen.getByText(/2.0 KB/)).toBeInTheDocument();
  });

  it("renders directory without size", () => {
    renderRow({ name: "images", is_directory: true, size: 0 });
    expect(screen.getByText("images")).toBeInTheDocument();
    expect(screen.queryByText(/KB|MB|B/)).not.toBeInTheDocument();
  });

  it("calls onDelete when delete clicked", () => {
    const { props } = renderRow({ name: "x.txt", is_directory: false, size: 100 });
    fireEvent.click(screen.getByLabelText("Delete"));
    expect(props.onDelete).toHaveBeenCalledWith("x.txt");
  });

  it("calls onDownload when download clicked (file)", () => {
    const { props } = renderRow({ name: "x.txt", is_directory: false, size: 100 });
    fireEvent.click(screen.getByLabelText("Download x.txt"));
    expect(props.onDownload).toHaveBeenCalledWith("x.txt");
  });

  it("does not show download for directory", () => {
    renderRow({ name: "folder", is_directory: true, size: 0 });
    expect(screen.queryByLabelText(/^Download/)).not.toBeInTheDocument();
  });

  it("calls onNavigate on directory click", () => {
    const { props } = renderRow({ name: "folder", is_directory: true, size: 0 });
    fireEvent.click(screen.getByText("folder"));
    expect(props.onNavigate).toHaveBeenCalledWith("folder");
  });

  it("preview button only for previewable extensions", () => {
    const { rerender } = render(
      <MantineProvider>
        <MemoryRouter>
          <Table><Table.Tbody>
            <FileRow
              file={{ name: "x.zip", is_directory: false, size: 100 }}
              index={0} selected={false}
              onToggleSelect={() => {}} onNavigate={() => {}}
              onDownload={() => {}} onCopyUrl={() => {}}
              onPreview={() => {}} onDelete={() => {}}
            />
          </Table.Tbody></Table>
        </MemoryRouter>
      </MantineProvider>,
    );
    expect(screen.queryByLabelText("Preview")).not.toBeInTheDocument();

    rerender(
      <MantineProvider>
        <MemoryRouter>
          <Table><Table.Tbody>
            <FileRow
              file={{ name: "img.png", is_directory: false, size: 100 }}
              index={0} selected={false}
              onToggleSelect={() => {}} onNavigate={() => {}}
              onDownload={() => {}} onCopyUrl={() => {}}
              onPreview={() => {}} onDelete={() => {}}
            />
          </Table.Tbody></Table>
        </MemoryRouter>
      </MantineProvider>,
    );
    expect(screen.getByLabelText("Preview")).toBeInTheDocument();
  });

  it("renders Delete disabled when me.disable_deletion is true", () => {
    vi.mocked(useMe).mockReturnValue({
      data: { disable_deletion: true },
    } as never);
    renderRow({ name: "x.txt", is_directory: false, size: 100 });
    expect(screen.getByLabelText("Delete")).toBeDisabled();
  });
});
