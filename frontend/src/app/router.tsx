import { createBrowserRouter } from "react-router-dom";
import { AdminGuard } from "@/components/AdminLayout/AdminGuard";
import { AdminLayout } from "@/components/AdminLayout/AdminLayout";
import { AppShellLayout } from "@/components/AppShell/AppShellLayout";
import { AuthGuard } from "@/components/AuthGuard/AuthGuard";
import { ErrorPage } from "@/pages/ErrorPage";
import { HomePage } from "@/pages/HomePage";
import { LoginPage } from "@/pages/LoginPage/LoginPage";
import { NotFoundPage } from "@/pages/NotFoundPage";
import { RolePage } from "@/pages/RolePage";
import { BucketPage } from "@/pages/BucketPage";
import { ChangePasswordPage } from "@/pages/ChangePasswordPage";
import { BansPage } from "@/pages/admin/BansPage";
import { RoleEditPage } from "@/pages/admin/RoleEditPage";
import { RoleNewPage } from "@/pages/admin/RoleNewPage";
import { RolesPage } from "@/pages/admin/RolesPage";
import { SettingsPage } from "@/pages/admin/SettingsPage";
import { UsersPage } from "@/pages/admin/UsersPage";

export const router = createBrowserRouter(
  [
    {
      path: "/login",
      element: <LoginPage />,
      errorElement: <ErrorPage />,
    },
    {
      element: <AuthGuard />,
      errorElement: <ErrorPage />,
      children: [
        {
          element: <AppShellLayout />,
          children: [
            { path: "/", element: <HomePage /> },
            { path: "/r/:roleId", element: <RolePage /> },
            { path: "/r/:roleId/b/:bucket", element: <BucketPage /> },
            { path: "/r/:roleId/b/:bucket/p/*", element: <BucketPage /> },
            { path: "/change-password", element: <ChangePasswordPage /> },
          ],
        },
        {
          element: <AdminGuard />,
          children: [
            {
              element: <AdminLayout />,
              children: [
                { path: "/admin/users", element: <UsersPage /> },
                { path: "/admin/bans", element: <BansPage /> },
                { path: "/admin/roles", element: <RolesPage /> },
                { path: "/admin/roles/new", element: <RoleNewPage /> },
                { path: "/admin/roles/:roleName", element: <RoleEditPage /> },
                { path: "/admin/settings", element: <SettingsPage /> },
              ],
            },
          ],
        },
      ],
    },
    {
      path: "*",
      element: <NotFoundPage />,
    },
  ],
  { basename: "/v2" },
);
