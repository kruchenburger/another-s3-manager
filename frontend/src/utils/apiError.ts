export class ApiError extends Error {
  readonly status: number;
  readonly body: unknown;

  constructor(status: number, message: string, body?: unknown) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.body = body;
  }

  isAuthError(): boolean {
    return this.status === 401;
  }
}

// Extract a human-readable message from an unknown thrown value.
// Used by TanStack Query onError handlers to show notifications.
export function getErrorMessage(err: unknown): string {
  if (err instanceof ApiError) {
    const body = err.body as { detail?: string } | undefined;
    return body?.detail ?? err.message;
  }
  if (err instanceof Error) return err.message;
  return "Unknown error";
}
