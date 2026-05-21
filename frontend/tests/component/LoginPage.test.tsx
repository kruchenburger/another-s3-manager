import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen } from "@testing-library/react";
import { MantineProvider } from "@mantine/core";
import { MemoryRouter } from "react-router-dom";
import { LoginPage } from "@/pages/LoginPage/LoginPage";
import { GITHUB_URL } from "@/constants/links";

const useAppInfoMock = vi.fn();
const useMeMock = vi.fn();
const useLoginMock = vi.fn();

vi.mock("@/hooks/useAppInfo", () => ({
  useAppInfo: () => useAppInfoMock(),
}));
vi.mock("@/features/auth/hooks/useMe", () => ({
  useMe: () => useMeMock(),
}));
vi.mock("@/features/auth/hooks/useLogin", () => ({
  useLogin: () => useLoginMock(),
}));
vi.mock("@/components/BurgerLogo/BurgerLogo", () => ({
  BurgerLogo: () => <span data-testid="burger-logo" />,
}));

function renderLogin() {
  return render(
    <MantineProvider>
      <MemoryRouter basename="/v2" initialEntries={["/v2/login"]}>
        <LoginPage />
      </MemoryRouter>
    </MantineProvider>,
  );
}

describe("LoginPage parity additions", () => {
  beforeEach(() => {
    useAppInfoMock.mockReset();
    useMeMock.mockReset();
    useLoginMock.mockReset();
    useMeMock.mockReturnValue({ data: undefined });
    useLoginMock.mockReturnValue({
      mutate: vi.fn(),
      isPending: false,
      isError: false,
    });
  });

  it("renders the tagline from app_description under the title", () => {
    useAppInfoMock.mockReturnValue({
      data: {
        app_name: "Another S3 Manager",
        app_description: "Lightweight S3 file management interface",
        app_version: "1.0.0",
      },
    });
    renderLogin();
    expect(
      screen.getByText(/lightweight s3 file management interface/i),
    ).toBeInTheDocument();
  });

  it("does NOT render the tagline when app_description is missing", () => {
    useAppInfoMock.mockReturnValue({
      data: {
        app_name: "Another S3 Manager",
        app_version: "1.0.0",
      },
    });
    renderLogin();
    // No tagline element should appear when the backend doesn't supply one.
    expect(
      screen.queryByText(/lightweight s3 file management interface/i),
    ).not.toBeInTheDocument();
  });

  it("renders v<version> + GitHub link in the footer band", () => {
    useAppInfoMock.mockReturnValue({
      data: {
        app_name: "Another S3 Manager",
        app_description: "x",
        app_version: "1.0.0",
      },
    });
    renderLogin();
    expect(screen.getByText(/^v1\.0\.0$/)).toBeInTheDocument();
    const link = screen.getByRole("link", { name: /source on github/i });
    expect(link).toHaveAttribute("href", GITHUB_URL);
    expect(link).toHaveAttribute("target", "_blank");
    expect(link).toHaveAttribute("rel", "noopener noreferrer");
  });

  it("does NOT render the footer band when app_version is 'dev'", () => {
    useAppInfoMock.mockReturnValue({
      data: {
        app_name: "Another S3 Manager",
        app_description: "x",
        app_version: "dev",
      },
    });
    renderLogin();
    expect(screen.queryByText(/source on github/i)).not.toBeInTheDocument();
  });

  it("does NOT render the footer band when appInfo is loading (no data)", () => {
    useAppInfoMock.mockReturnValue({ data: undefined });
    renderLogin();
    expect(screen.queryByText(/source on github/i)).not.toBeInTheDocument();
  });

  it("uses fallback app name when appInfo is not yet loaded", () => {
    useAppInfoMock.mockReturnValue({ data: undefined });
    renderLogin();
    expect(screen.getByText(/another s3 manager/i)).toBeInTheDocument();
  });
});
