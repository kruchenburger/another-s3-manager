import { RouterProvider } from "react-router-dom";
import { AppProviders } from "@/app/providers";
import { ErrorBoundary } from "@/components/ErrorBoundary/ErrorBoundary";
import { router } from "@/app/router";

export function App() {
  return (
    <ErrorBoundary>
      <AppProviders>
        <RouterProvider router={router} />
      </AppProviders>
    </ErrorBoundary>
  );
}
