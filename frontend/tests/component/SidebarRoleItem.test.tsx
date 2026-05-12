import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, fireEvent } from "@testing-library/react";
import { MantineProvider } from "@mantine/core";
import { MemoryRouter } from "react-router-dom";
import { ApiError } from "@/utils/apiError";

const useBucketsMock = vi.fn();
vi.mock("@/features/files/hooks/useBuckets", () => ({
  useBuckets: (...args: unknown[]) => useBucketsMock(...args),
}));

import { SidebarRoleItem } from "@/components/Sidebar/SidebarRoleItem";

function renderItem() {
  return render(
    <MantineProvider>
      <MemoryRouter>
        <SidebarRoleItem role="MyRole" collapsed={false} />
      </MemoryRouter>
    </MantineProvider>,
  );
}

describe("SidebarRoleItem error states", () => {
  beforeEach(() => useBucketsMock.mockReset());

  it("renders a generic warning sub-item when expanded and the hook returns a 500", () => {
    useBucketsMock.mockReturnValue({
      data: undefined,
      isLoading: false,
      error: new ApiError(500, "Internal Server Error", {
        detail: { code: "INTERNAL", message: "Server error — see logs" },
      }),
    });
    renderItem();
    // Click chevron to expand
    fireEvent.click(screen.getByLabelText(/expand myrole/i));
    expect(screen.getByText(/couldn't load buckets/i)).toBeInTheDocument();
    expect(screen.getByText("Server error — see logs")).toBeInTheDocument();
    // 403-specific copy must NOT appear for a 500.
    expect(
      screen.queryByText(/cannot list buckets — open this role to fix/i),
    ).not.toBeInTheDocument();
  });

  it("keeps rendering the 403 sub-item unchanged", () => {
    useBucketsMock.mockReturnValue({
      data: undefined,
      isLoading: false,
      error: new ApiError(403, "Forbidden", { detail: "Access denied" }),
    });
    renderItem();
    fireEvent.click(screen.getByLabelText(/expand myrole/i));
    expect(screen.getByText(/cannot list buckets/i)).toBeInTheDocument();
  });

  it("renders bucket items normally when there is no error", () => {
    useBucketsMock.mockReturnValue({
      data: ["bucket-a", "bucket-b"],
      isLoading: false,
      error: null,
    });
    renderItem();
    fireEvent.click(screen.getByLabelText(/expand myrole/i));
    expect(screen.getByText("bucket-a")).toBeInTheDocument();
    expect(screen.getByText("bucket-b")).toBeInTheDocument();
    expect(screen.queryByText(/couldn't load buckets/i)).not.toBeInTheDocument();
  });
});
