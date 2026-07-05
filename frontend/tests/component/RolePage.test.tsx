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
      error: new ApiError(403, "forbidden", {
        detail: "Your credentials don't have permission to list all buckets. This is normal for scoped tokens.",
      }),
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

  it("does not redirect when stale cached buckets coexist with a fresh 403 error", () => {
    // Race scenario: TanStack Query returns the previously-cached single bucket
    // while a concurrent refresh fails with 403 (e.g. the role's credentials
    // just lost permission). The user must land on the 403 EmptyState, not be
    // silently redirected past it AND not on a blank screen.
    useBucketsMock.mockReturnValue({
      data: ["stale-bucket"],
      isLoading: false,
      error: new ApiError(403, "forbidden", {
        detail: "Your credentials don't have permission to list all buckets.",
      }),
    });
    renderPage();
    expect(navigateMock).not.toHaveBeenCalled();
    // 403 EmptyState should render, not a blank `return null` from the
    // single-bucket guard. Match on the EmptyState title text.
    expect(
      screen.getByText(/cannot list buckets for this role/i),
    ).toBeInTheDocument();
  });
});

describe("RolePage 403 message disambiguation", () => {
  // The previous version rendered the same "configure Allowed Buckets" copy for
  // BOTH a role-level deny (user simply doesn't have the role) AND an
  // S3-credentials-level deny (role has the wrong credentials). The role-level
  // case had nothing to do with allowed_buckets, so the hint was misleading.
  // These tests pin the two backend messages to two distinct UI branches.

  beforeEach(() => {
    navigateMock.mockReset();
    useBucketsMock.mockReset();
  });

  it("shows 'Role not available' copy when backend says user can't use the role", () => {
    useBucketsMock.mockReturnValue({
      data: undefined,
      isLoading: false,
      error: new ApiError(403, "forbidden", {
        detail: "Access denied: You don't have permission to use role 'MinIO-e2e'",
      }),
    });
    renderPage();

    expect(screen.getByText(/role not available/i)).toBeInTheDocument();
    expect(screen.getByText(/grant you access to this role/i)).toBeInTheDocument();
    // The misleading "Allowed Buckets" hint must NOT appear for this case.
    expect(screen.queryByText(/allowed buckets/i)).not.toBeInTheDocument();
    // The role-level message must be surfaced verbatim.
    expect(screen.getByText(/Access denied: You don't have permission/i)).toBeInTheDocument();
  });

  it("shows 'Cannot list buckets' copy when backend says credentials lack ListAllMyBuckets", () => {
    useBucketsMock.mockReturnValue({
      data: undefined,
      isLoading: false,
      error: new ApiError(403, "forbidden", {
        detail:
          "Your credentials don't have permission to list all buckets. This is normal for scoped tokens (R2, MinIO, AWS IAM with bucket-scoped policies).",
      }),
    });
    renderPage();

    expect(screen.getByText(/cannot list buckets for this role/i)).toBeInTheDocument();
    expect(screen.getByText(/allowed buckets/i)).toBeInTheDocument();
    // The role-level title must NOT appear for this case.
    expect(screen.queryByText(/role not available/i)).not.toBeInTheDocument();
  });
});

describe("RolePage non-403 errors", () => {
  beforeEach(() => {
    navigateMock.mockReset();
    useBucketsMock.mockReset();
  });

  it("renders the generic error state for a 500 (not the empty-buckets state)", () => {
    useBucketsMock.mockReturnValue({
      data: undefined,
      isLoading: false,
      error: new ApiError(500, "Internal Server Error", {
        detail: { code: "INTERNAL", message: "Server error — see logs" },
      }),
    });
    renderPage();
    expect(screen.getByText(/couldn't load buckets/i)).toBeInTheDocument();
    expect(screen.getByText("Server error — see logs")).toBeInTheDocument();
    // Empty-buckets EmptyState must NOT render when there is an error.
    expect(screen.queryByText(/no buckets accessible/i)).not.toBeInTheDocument();
    // 403 EmptyState must NOT render either.
    expect(screen.queryByText(/cannot list buckets for this role/i)).not.toBeInTheDocument();
  });

  it("renders the generic error state when stale buckets coexist with a 500", () => {
    useBucketsMock.mockReturnValue({
      data: ["stale-bucket"],
      isLoading: false,
      error: new ApiError(500, "Internal Server Error", {
        detail: { code: "INTERNAL", message: "Server error — see logs" },
      }),
    });
    renderPage();
    expect(screen.getByText(/couldn't load buckets/i)).toBeInTheDocument();
    expect(screen.queryByText("stale-bucket")).not.toBeInTheDocument();
  });
});
