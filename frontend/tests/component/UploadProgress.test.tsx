import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";
import { MantineProvider } from "@mantine/core";
import { UploadProgress } from "@/components/Upload/UploadProgress";

describe("UploadProgress", () => {
  it("shows 'Uploading 3 files'", () => {
    render(
      <MantineProvider>
        <UploadProgress
          items={[
            { name: "a.txt", status: "uploading" },
            { name: "b.txt", status: "pending" },
            { name: "c.txt", status: "pending" },
          ]}
        />
      </MantineProvider>,
    );
    expect(screen.getByText(/Uploading 3 files/)).toBeInTheDocument();
    expect(screen.getByText(/0\/3/)).toBeInTheDocument();
  });

  it("shows error count when failures occur", () => {
    render(
      <MantineProvider>
        <UploadProgress
          items={[
            { name: "a.txt", status: "done" },
            { name: "b.txt", status: "error", error: "boom" },
            { name: "c.txt", status: "done" },
          ]}
        />
      </MantineProvider>,
    );
    expect(screen.getByText(/2\/3.*1 failed/)).toBeInTheDocument();
  });

  it("uses singular for one file", () => {
    render(
      <MantineProvider>
        <UploadProgress items={[{ name: "x.txt", status: "uploading" }]} />
      </MantineProvider>,
    );
    expect(screen.getByText(/Uploading 1 file$/)).toBeInTheDocument();
  });
});
