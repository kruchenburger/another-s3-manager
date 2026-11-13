import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen } from "@testing-library/react";
import { MantineProvider } from "@mantine/core";
import { MemoryRouter, Route, Routes } from "react-router-dom";

import {
  AuthGuard,
  SESSION_ENDED_NOTIFICATION_ID,
} from "@/components/AuthGuard/AuthGuard";
import { ApiError } from "@/utils/apiError";

vi.mock("@/features/auth/hooks/useMe", () => ({
  useMe: vi.fn(),
}));
vi.mock("@mantine/notifications", () => ({
  notifications: { show: vi.fn() },
}));
import { useMe } from "@/features/auth/hooks/useMe";
import { notifications } from "@mantine/notifications";

function mockMe(value: Partial<ReturnType<typeof useMe>>) {
  vi.mocked(useMe).mockReturnValue({
    isLoading: false,
    ...value,
  } as unknown as ReturnType<typeof useMe>);
}

function renderGuard() {
  return render(
    <MantineProvider>
      <MemoryRouter initialEntries={["/buckets"]}>
        <Routes>
          <Route element={<AuthGuard />}>
            <Route path="/buckets" element={<div>protected content</div>} />
          </Route>
          <Route path="/login" element={<div>login screen</div>} />
        </Routes>
      </MemoryRouter>
    </MantineProvider>,
  );
}

describe("AuthGuard", () => {
  beforeEach(() => vi.clearAllMocks());

  it("redirects to sign-in with a 'Session ended' notice when a signed-in session gets 401", () => {
    mockMe({
      data: { username: "alice" } as ReturnType<typeof useMe>["data"],
      error: new ApiError(401, "Not authenticated"),
    });
    renderGuard();
    expect(screen.getByText("login screen")).toBeInTheDocument();
    expect(notifications.show).toHaveBeenCalledTimes(1);
    expect(vi.mocked(notifications.show).mock.calls[0][0]).toMatchObject({
      id: SESSION_ENDED_NOTIFICATION_ID,
      title: "Session ended",
    });
  });

  it("redirects to sign-in silently on a first visit without a session", () => {
    mockMe({ data: undefined, error: new ApiError(401, "Not authenticated") });
    renderGuard();
    expect(screen.getByText("login screen")).toBeInTheDocument();
    expect(notifications.show).not.toHaveBeenCalled();
  });

  it("renders protected content for a signed-in user", () => {
    mockMe({
      data: { username: "alice" } as ReturnType<typeof useMe>["data"],
      error: null,
    });
    renderGuard();
    expect(screen.getByText("protected content")).toBeInTheDocument();
    expect(notifications.show).not.toHaveBeenCalled();
  });
});
