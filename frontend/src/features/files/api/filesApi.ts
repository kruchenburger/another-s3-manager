import { apiRequest } from "@/hooks/useApiClient";
import { ApiError } from "@/utils/apiError";
import { getCsrfToken } from "@/utils/csrf";
import type { BucketList, ListFilesPage } from "@/types/api";

export async function listBuckets(role: string): Promise<BucketList> {
  const params = new URLSearchParams({ role });
  return apiRequest<BucketList>(`/api/buckets?${params}`);
}

// Paginated file listing — the route returns `{directories, files, next_token, has_more}`
// when `max_keys` is set. The /v2 UI is the only caller; vanilla UI and MCP hit
// the legacy code path on the backend (without max_keys) and don't go through here.
export async function listFiles(
  bucket: string,
  role: string,
  path: string,
  opts: { maxKeys: number; continuationToken?: string },
): Promise<ListFilesPage> {
  const params = new URLSearchParams({ role });
  if (path) params.set("path", path);
  params.set("max_keys", String(opts.maxKeys));
  if (opts.continuationToken) {
    params.set("continuation_token", opts.continuationToken);
  }
  return apiRequest<ListFilesPage>(
    `/api/buckets/${encodeURIComponent(bucket)}/files?${params}`,
  );
}

export interface UploadFileOptions {
  /** Called periodically with 0..100 percent of the file body uploaded. The
   *  browser fires `progress` events on the request body stream as bytes
   *  leave the network buffer; for files smaller than ~1MB this can fire
   *  zero or one times. */
  onProgress?: (percent: number) => void;
  /** AbortSignal — when triggered, the in-flight upload is cancelled and
   *  the promise rejects with `new DOMException("...", "AbortError")`. */
  signal?: AbortSignal;
}

/**
 * POST a single file to the upload endpoint.
 *
 * Uses XMLHttpRequest (not fetch) because the fetch API has no built-in
 * upload-progress events and no streaming-request abort that works in all
 * supported browsers. XHR's `upload.onprogress` and `xhr.abort()` cover both
 * features needed for a UX that respects the user's time on large or many-file
 * uploads.
 *
 * Throws an `ApiError` on non-2xx (with the parsed JSON body when available),
 * or a DOMException with `name === "AbortError"` if the caller's signal fires.
 */
export function uploadFile(
  bucket: string,
  role: string,
  key: string,
  file: File,
  options: UploadFileOptions = {},
): Promise<void> {
  return new Promise((resolve, reject) => {
    // Abort BEFORE we even open the request — bail out without sending.
    if (options.signal?.aborted) {
      reject(new DOMException("Upload aborted", "AbortError"));
      return;
    }

    const body = new FormData();
    body.append("file", file);
    body.append("key", key);
    body.append("role", role);

    const xhr = new XMLHttpRequest();
    xhr.open("POST", `/api/buckets/${encodeURIComponent(bucket)}/upload`, true);
    xhr.withCredentials = true;
    const csrf = getCsrfToken();
    if (csrf) xhr.setRequestHeader("X-CSRF-Token", csrf);
    xhr.setRequestHeader("Accept", "application/json");

    if (options.onProgress) {
      xhr.upload.onprogress = (event) => {
        if (event.lengthComputable && event.total > 0) {
          const percent = Math.round((event.loaded / event.total) * 100);
          options.onProgress!(percent);
        }
      };
    }

    // Centralised cleanup so we never leak the abort listener on the (often
    // batch-shared) AbortSignal. Every terminal handler (`onload`, `onerror`,
    // `onabort`) calls this first thing.
    const cleanup = () => {
      if (options.signal) options.signal.removeEventListener("abort", onAbort);
    };

    const onAbort = () => {
      // Trigger XHR cancellation. The actual promise rejection happens in
      // `xhr.onabort` so browser-initiated aborts (e.g. page navigation) are
      // also covered — without `xhr.onabort` they would leave the promise
      // hanging forever.
      xhr.abort();
    };
    if (options.signal) {
      options.signal.addEventListener("abort", onAbort);
    }

    xhr.onload = () => {
      cleanup();
      if (xhr.status >= 200 && xhr.status < 300) {
        resolve();
        return;
      }
      // Try to parse the server's structured error body for the toast.
      let body: unknown = null;
      try {
        body = JSON.parse(xhr.responseText);
      } catch {
        // non-JSON error body — keep null
      }
      reject(new ApiError(xhr.status, xhr.statusText || `HTTP ${xhr.status}`, body));
    };

    xhr.onerror = () => {
      cleanup();
      // Network failure — no HTTP status. Mirror the apiRequest fetch path which
      // surfaces this as a TypeError; we surface as an ApiError(0, ...) so the
      // upload toast has a consistent shape across HTTP and network failures.
      reject(new ApiError(0, "Network error during upload", null));
    };

    xhr.onabort = () => {
      cleanup();
      reject(new DOMException("Upload aborted", "AbortError"));
    };

    xhr.send(body);
  });
}

export async function deleteFile(bucket: string, role: string, path: string): Promise<void> {
  // path can be a folder (ends with /) — backend handles recursive delete
  const params = new URLSearchParams({ role, path });
  await apiRequest<void>(`/api/buckets/${encodeURIComponent(bucket)}/files?${params}`, {
    method: "DELETE",
  });
}

export function buildDownloadUrl(bucket: string, role: string, path: string): string {
  // Browser-triggered download via <a href> — relies on cookie auth (same-origin GET).
  const params = new URLSearchParams({ role, path });
  return `/api/buckets/${encodeURIComponent(bucket)}/download?${params}`;
}

export interface PresignedUrlResponse {
  url: string;
  /** ISO8601 UTC timestamp when the URL stops working. */
  expires_at: string;
}

/**
 * Fetch a short-lived (1h) presigned GET URL for a single object.
 *
 * Use this for shareable links and for <img>/<video> tags that can't carry
 * the auth cookie reliably (third-party CDNs, copy-to-clipboard flows). For
 * the regular Download button (browser-triggered <a href>), keep using
 * {@link buildDownloadUrl}.
 */
export async function getPresignedDownloadUrl(
  bucket: string,
  role: string,
  path: string,
): Promise<PresignedUrlResponse> {
  const params = new URLSearchParams({ role, path });
  return apiRequest<PresignedUrlResponse>(
    `/api/buckets/${encodeURIComponent(bucket)}/presigned?${params}`,
  );
}
