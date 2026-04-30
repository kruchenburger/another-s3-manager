import { createBrowserRouter } from "react-router-dom";
import { AppShellLayout } from "@/components/AppShell/AppShellLayout";
import { AuthGuard } from "@/components/AuthGuard/AuthGuard";
import { ErrorPage } from "@/pages/ErrorPage";
import { HomePage } from "@/pages/HomePage";
import { LoginPage } from "@/pages/LoginPage/LoginPage";
import { NotFoundPage } from "@/pages/NotFoundPage";

// basename "/v2" matches the FastAPI mount in main.py.
// All client URLs in the app are written without the /v2 prefix; the router
// adds it transparently.
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
            // Phase 3+ feature routes nest here:
            //   { path: "/buckets", element: <BucketsPage /> },
            //   { path: "/admin/*", element: <AdminLayout />, children: [...] },
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
