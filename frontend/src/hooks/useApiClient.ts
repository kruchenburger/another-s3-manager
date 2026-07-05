import { ApiError } from "@/utils/apiError";
import { getCsrfToken } from "@/utils/csrf";

type Method = "GET" | "POST" | "PUT" | "PATCH" | "DELETE";

interface RequestOptions {
  method?: Method;
  body?: BodyInit | null;
  headers?: Record<string, string>;
}

const MUTATING: ReadonlySet<Method> = new Set(["POST", "PUT", "PATCH", "DELETE"]);

// Thin fetch wrapper:
//   - credentials: "include" so the auth cookie rides along
//   - X-CSRF-Token attached on mutating methods (cookie-jar CSRF defence)
//   - throws ApiError on non-2xx with the parsed body for upstream handling
export async function apiRequest<T = unknown>(url: string, options: RequestOptions = {}): Promise<T> {
  const method: Method = options.method ?? "GET";

  const headers: Record<string, string> = {
    Accept: "application/json",
    ...(options.headers ?? {}),
  };

  if (MUTATING.has(method)) {
    const csrf = getCsrfToken();
    if (csrf) headers["X-CSRF-Token"] = csrf;
  }

  const response = await fetch(url, {
    method,
    credentials: "include",
    headers,
    body: options.body ?? null,
  });

  if (!response.ok) {
    let body: unknown = null;
    try {
      body = await response.json();
    } catch {
      // non-JSON error body — keep null
    }
    throw new ApiError(response.status, response.statusText || `HTTP ${response.status}`, body);
  }

  // 204 No Content
  if (response.status === 204) return undefined as T;

  const contentType = response.headers.get("content-type") ?? "";
  if (contentType.includes("application/json")) {
    return (await response.json()) as T;
  }
  return undefined as T;
}
