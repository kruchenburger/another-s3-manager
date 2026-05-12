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

// Detail shape evolves: legacy endpoints return `detail: "string"`; the file-ops
// routes touched in error-handling PR1 return `detail: {code, message}`.
type ApiErrorDetailDict = { code?: string; message?: string };
type ApiErrorBody = { detail?: string | ApiErrorDetailDict } | undefined;

function readDetail(err: ApiError): string | ApiErrorDetailDict | undefined {
  return (err.body as ApiErrorBody)?.detail;
}

// Extract a human-readable message from an unknown thrown value. Used by
// TanStack Query onError handlers and the QueryErrorState component.
//
// Resolution order:
//   1. ApiError + dict detail with a `message` field → that message
//   2. ApiError + string detail → the string
//   3. ApiError with body supplied but no usable detail → bare message (trust the
//      server's statusText as the message — don't double-prefix)
//   4. ApiError with no body at all → `<status> <statusText>` (e.g. "502 Bad Gateway")
//   5. TypeError (fetch rejection / network failure) → friendly "network error"
//   6. Any other Error → its `.message`
//   7. Anything else (null, undefined, primitive) → "Unknown error"
export function getErrorMessage(err: unknown): string {
  if (err instanceof ApiError) {
    const detail = readDetail(err);
    if (typeof detail === "string" && detail.length > 0) return detail;
    if (detail && typeof detail === "object" && typeof detail.message === "string") {
      return detail.message;
    }
    // Body was supplied but had no usable detail field (e.g. {}). Trust the
    // server's statusText as the message — don't double-prefix.
    if (err.body !== undefined) {
      return err.message || `HTTP ${err.status}`;
    }
    // No body at all — likely a network-layer failure where statusText is the
    // only signal. Prefix with status for context (e.g. "502 Bad Gateway").
    if (err.message) {
      return `${err.status} ${err.message}`;
    }
    return `HTTP ${err.status}`;
  }
  if (err instanceof TypeError) {
    // `fetch` rejects with TypeError on network failure (offline, DNS, CORS).
    return "Network error — check your connection.";
  }
  if (err instanceof Error) return err.message;
  return "Unknown error";
}

// Extract the structured `code` from an ApiError's dict-shape detail (PR1).
// Returns null for legacy string detail, missing detail, or non-ApiError values.
// Reserved for future per-code UI (e.g. "Open admin to fix" CTA when
// code === "S3_INVALID_REGION").
export function getErrorCode(err: unknown): string | null {
  if (!(err instanceof ApiError)) return null;
  const detail = readDetail(err);
  if (detail && typeof detail === "object" && typeof detail.code === "string") {
    return detail.code;
  }
  return null;
}
