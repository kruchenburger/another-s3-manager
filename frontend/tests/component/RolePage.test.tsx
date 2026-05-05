import { render, screen } from "@testing-library/react";
import { MantineProvider } from "@mantine/core";
import { MemoryRouter } from "react-router-dom";
import { describe, it, expect, vi, beforeEach } from "vitest";
import { RolePage } from "@/pages/RolePage";
import { ApiError } from "@/utils/apiError";

const navigateMock = vi.fn();

vi.mock("react-router-dom", async () => {
  const actual =
    await vi.importActual<typeof import("react-router-dom")>("react-router-dom");
  return {
    ...actual,
    useNavigate: () => navigateMock,
    useParams: () => ({ roleId: "my-role" }),
  };
});

const useBucketsMock = vi.fn();
vi.mock("@/features/files/hooks/useBuckets", () => ({
  useBuckets: (...args: unknown[]) => useBucketsMock(...args),
}));

vi.mock("@/features/auth/hooks/useMe", () => ({
  useMe: () => ({ data: { is_admin: false } }),
}));

function renderPage() {
  return render(
    <MantineProvider>
      <MemoryRouter basename="/v2" initialEntries={["/v2/r/my-role"]}>
        <RolePage />
      </MemoryRouter>
    </MantineProvider>,
  );
}

describe("RolePage auto-open single bucket", () => {
  beforeEach(() => {
    navigateMock.mockReset();
    useBucketsMock.mockReset();
  });

  it("redirects to the only bucket when length === 1", () => {
    useBucketsMock.mockReturnValue({
      data: ["only-bucket"],
      isLoading: false,
      error: null,
    });
    renderPage();
    expect(navigateMock).toHaveBeenCalledTimes(1);
    expect(navigateMock).toHaveBeenCalledWith("/r/my-role/b/only-bucket", {
      replace: true,
    });
  });

  it("does not redirect when more than one bucket", () => {
    useBucketsMock.mockReturnValue({
      data: ["a", "b"],
      isLoading: false,
      error: null,
    });
    renderPage();
    expect(navigateMock).not.toHaveBeenCalled();
    expect(screen.getByRole("table")).toBeInTheDocument();
  });

  it("does not redirect on 403 error", () => {
    useBucketsMock.mockReturnValue({
      data: undefined,
      isLoading: false,
      error: new ApiError(403, "forbidden"),
    });
    renderPage();
    expect(navigateMock).not.toHaveBeenCalled();
  });

  it("does not redirect while loading", () => {
    useBucketsMock.mockReturnValue({
      data: undefined,
      isLoading: true,
      error: null,
    });
    renderPage();
    expect(navigateMock).not.toHaveBeenCalled();
  });

  it("does not redirect with zero buckets", () => {
    useBucketsMock.mockReturnValue({
      data: [],
      isLoading: false,
      error: null,
    });
    renderPage();
    expect(navigateMock).not.toHaveBeenCalled();
  });
});
