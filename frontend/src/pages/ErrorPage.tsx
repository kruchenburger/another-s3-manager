import { useRouteError, isRouteErrorResponse } from "react-router-dom";
import { ErrorFallback } from "@/components/ErrorBoundary/ErrorFallback";

export function ErrorPage() {
  const error = useRouteError();

  let message = "Unknown routing error";
  if (isRouteErrorResponse(error)) {
    message = `${error.status} ${error.statusText}`;
  } else if (error instanceof Error) {
    message = error.message;
  }

  return <ErrorFallback error={new Error(message)} onReset={() => window.location.assign("/v2/")} />;
}
