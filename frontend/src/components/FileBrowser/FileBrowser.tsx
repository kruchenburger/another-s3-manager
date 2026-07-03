import { useMemo, useRef, useState, useCallback } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { filesQueryKey } from "@/features/files/hooks/useFiles";
import { useShiftSelect } from "./useShiftSelect";
import { Anchor, Badge, CloseButton, Group, Text } from "@mantine/core";
import { useDebouncedValue } from "@mantine/hooks";
import { DelayedLoader } from "@/components/DelayedLoader/DelayedLoader";
import { notifications } from "@mantine/notifications";
import { useNavigate, useParams } from "react-router-dom";
import { useFiles } from "@/features/files/hooks/useFiles";
import {
  useFileSearch,
  fileSearchFolderKey,
} from "@/features/files/hooks/useFileSearch";
import { useDelete } from "@/features/files/hooks/useDelete";
import { useUpload } from "@/features/files/hooks/useUpload";
import {
  buildDownloadUrl,
  deleteFile,
  getPresignedDownloadUrl,
} from "@/features/files/api/filesApi";
import { useMe } from "@/features/auth/hooks/useMe";
import { useDisplayMode } from "@/hooks/useDisplayMode";
import { useConfig } from "@/hooks/useConfig";
import { joinPath, decodePath } from "@/utils/pathUtils";
import { ApiError, getErrorMessage } from "@/utils/apiError";
import { formatBytes } from "@/utils/formatBytes";
import { formatTimeOfDay } from "@/utils/formatDate";
import { formatDuration } from "@/utils/formatDuration";
import { showToast, TOAST_DURATIONS } from "@/utils/toast";
import { ConfirmDeleteModal } from "@/components/Confirm/ConfirmDeleteModal";
import { PreviewModal } from "@/components/Preview/PreviewModal";
import { UploadDropZone } from "@/components/Upload/UploadDropZone";
import {
  UploadProgress,
  type UploadProgressItem,
} from "@/components/Upload/UploadProgress";
import { UploadSummary } from "@/components/Upload/UploadSummary";
import {
  FolderUploadHintModal,
  hasDismissedFolderUploadHint,
} from "@/components/Upload/FolderUploadHintModal";
import {
  type FileWithRelativePath,
  filesFromFolderInput,
} from "@/utils/folderUpload";
import { BucketPageHeader } from "./BucketPageHeader";
import { FileBrowserHeader } from "./FileBrowserHeader";
import { BulkActionBar } from "./BulkActionBar";
import { FileTable } from "./FileTable";
import { FileGrid } from "./FileGrid";
import { FileBrowserEmptyState } from "./FileBrowserEmptyState";
import { FileBrowserLoadMoreFooter } from "./FileBrowserLoadMoreFooter";
import { BulkDeleteProgress } from "@/components/FileBrowser/BulkDeleteProgress";
import { QueryErrorState } from "@/components/QueryErrorState/QueryErrorState";
import { ScrollToTopButton } from "@/components/ScrollToTopButton/ScrollToTopButton";
import classes from "./FileBrowser.module.css";

export function FileBrowser() {
  const params = useParams<{ roleId: string; bucket: string; "*": string }>();
  const roleId = decodeURIComponent(params.roleId ?? "");
  const bucket = decodeURIComponent(params.bucket ?? "");
  const pathFromUrl = decodePath(params["*"] ?? "");
  const navigate = useNavigate();

  const { data: config } = useConfig();
  const lazyLoadingEnabled = config?.enable_lazy_loading ?? true;
  const presignedDefaultTtl = config?.presigned_url_default_ttl ?? 3600;
  const presignedMaxTtl = config?.presigned_url_max_ttl ?? 604800;

  const [serverSearchTerm, setServerSearchTerm] = useState<string | null>(null);
  const serverSearchActive = serverSearchTerm !== null;
  const [searchQuery, setSearchQuery] = useState("");

  const folder = useFiles(bucket, roleId, pathFromUrl);
  const search = useFileSearch(bucket, roleId, pathFromUrl, serverSearchTerm ?? "");
  const active = serverSearchActive ? search : folder;

  const {
    directories,
    files,
    truncated,
    loadMore,
    loadAll,
    isFetching,
    isFetchingNextPage,
    isFetchNextPageError,
    error,
  } = active;

  // Reset server-search when role/bucket/path changes. FileBrowser stays mounted
  // across folder navigation, so serverSearchTerm would otherwise leak into the
  // new folder. Render-time reset (React's documented "adjust state on prop
  // change" pattern) — not an effect.
  const contextKey = `${roleId}/${bucket}/${pathFromUrl}`;
  const [prevContextKey, setPrevContextKey] = useState(contextKey);
  if (contextKey !== prevContextKey) {
    setPrevContextKey(contextKey);
    setServerSearchTerm(null);
    setSearchQuery("");
  }

  // All loaded items, directories first (vanilla parity). Single source of
  // truth for filtering and every .find(name === ...) lookup below.
  const items = useMemo(
    () => [...directories, ...files],
    [directories, files],
  );

  const queryClient = useQueryClient();
  const deleteMutation = useDelete();
  const uploadMutation = useUpload();
  const { mode, setMode } = useDisplayMode(roleId, bucket);
  const me = useMe();
  const disableDeletion = me.data?.disable_deletion ?? false;

  const {
    selected,
    handleToggle: handleToggleSelect,
    toggleAll: handleToggleAll,
    clear: clearSelection,
  } = useShiftSelect();
  const [confirmOpen, setConfirmOpen] = useState(false);
  const [uploadHint, setUploadHint] = useState<{
    open: boolean;
    mode: "files" | "folder";
  }>({
    open: false,
    mode: "files",
  });
  const pendingDelete = useRef<string[]>([]);
  const fileInputRef = useRef<HTMLInputElement>(null);
  const folderInputRef = useRef<HTMLInputElement>(null);
  const scrollRef = useRef<HTMLDivElement>(null);

  const [debouncedQuery] = useDebouncedValue(searchQuery, 200);

  const filteredItems = useMemo(() => {
    if (serverSearchActive) return items;
    if (!debouncedQuery) return items;
    const q = debouncedQuery.toLowerCase();
    return items.filter((f) => f.name.toLowerCase().includes(q));
  }, [items, debouncedQuery, serverSearchActive]);

  const navigateToFolder = (folderName: string) => {
    clearSelection();
    setSearchQuery("");
    setServerSearchTerm(null);
    const next = joinPath(pathFromUrl, folderName);
    const encoded = next.split("/").map(encodeURIComponent).join("/");
    navigate(
      `/r/${encodeURIComponent(roleId)}/b/${encodeURIComponent(bucket)}/p/${encoded}`,
    );
  };

  const enterServerSearch = (term: string) => {
    const trimmed = term.trim();
    if (!trimmed) return;
    setServerSearchTerm(trimmed);
    clearSelection();
    if (scrollRef.current) scrollRef.current.scrollTop = 0;
  };

  const exitServerSearch = () => {
    setServerSearchTerm(null);
    // Also clear the filter box: leaving the committed term in it would, back in
    // folder mode, hide every loaded item that doesn't contain that term (the
    // term was chosen precisely because it ISN'T in the loaded chunk) — landing
    // the user on a confusingly empty folder. Clearing returns the full folder.
    setSearchQuery("");
    if (scrollRef.current) scrollRef.current.scrollTop = 0;
  };

  const handleDownload = async (name: string): Promise<void> => {
    const fullPath = joinPath(pathFromUrl, name);
    const url = buildDownloadUrl(bucket, roleId, fullPath);
    try {
      const response = await fetch(url, { credentials: "include" });
      if (!response.ok) {
        // Surface the server's error message instead of navigating to the raw error page.
        let body: unknown;
        try {
          body = await response.json();
        } catch {
          body = undefined;
        }
        throw new ApiError(response.status, response.statusText, body);
      }
      const blob = await response.blob();
      // Filename: prefer the RFC 5987 `filename*=UTF-8''…` variant (preserves
      // Cyrillic/CJK), fall back to the ASCII `filename=` param, then to the
      // file's display name. The backend emits both per RFC 5987, with the
      // ASCII param first — a naive `.match()` would pick that one and lose
      // non-ASCII characters.
      const disposition = response.headers.get("Content-Disposition") ?? "";
      const matches = Array.from(
        disposition.matchAll(/filename(\*?)=(?:UTF-8'')?"?([^";]+)"?/gi),
      );
      const starred = matches.find((m) => m[1] === "*");
      const plain = matches.find((m) => m[1] === "");
      const rawFilename = starred?.[2] ?? plain?.[2];
      const filename = rawFilename ? decodeURIComponent(rawFilename) : name;
      const blobUrl = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = blobUrl;
      link.download = filename;
      document.body.appendChild(link);
      link.click();
      link.remove();
      URL.revokeObjectURL(blobUrl);
    } catch (e) {
      showToast({
        color: "red",
        title: "Download failed",
        message: getErrorMessage(e),
        autoClose: TOAST_DURATIONS.error,
      });
    }
  };

  const handleCopyUrl = async (name: string, ttlSeconds?: number) => {
    const fullPath = joinPath(pathFromUrl, name);
    try {
      const { url, expires_at, expires_in, warning } = await getPresignedDownloadUrl(
        bucket,
        roleId,
        fullPath,
        ttlSeconds,
      );
      await navigator.clipboard.writeText(url);
      const base = `${name} — anyone with this link can download it until ${formatTimeOfDay(expires_at)} (expires in ${formatDuration(expires_in)}). No login needed.`;
      showToast({
        color: warning ? "yellow" : "green",
        title: "Presigned URL copied",
        message: warning ? `${base}\n${warning}` : base,
        autoClose: TOAST_DURATIONS.infoLong,
      });
    } catch (e) {
      showToast({
        color: "red",
        title: "Copy failed",
        message: e instanceof Error ? e.message : "unknown error",
        autoClose: TOAST_DURATIONS.error,
      });
    }
  };

  const [bulkCopying, setBulkCopying] = useState(false);
  const bulkCopyingRef = useRef(false);

  const handleBulkCopyUrl = async (ttlSeconds?: number) => {
    // Guard against double-submit: this fires N presigned-URL requests via
    // Promise.all; a rapid second click before the button's disabled state
    // renders would start a concurrent batch (same bug class fixed for
    // Load-more/Load-all). The ref closes the click→render-latency gap.
    if (bulkCopyingRef.current) return;
    bulkCopyingRef.current = true;
    setBulkCopying(true);
    const names = Array.from(selected);
    try {
      const responses = await Promise.all(
        names.map((name) =>
          getPresignedDownloadUrl(bucket, roleId, joinPath(pathFromUrl, name), ttlSeconds),
        ),
      );
      const urls = responses.map((r) => r.url).join("\n");
      await navigator.clipboard.writeText(urls);
      const first = responses[0];
      const warning = responses.find((r) => r.warning)?.warning;
      const base = first
        ? `Anyone with these links can download until ${formatTimeOfDay(first.expires_at)} (expires in ${formatDuration(first.expires_in)}). No login needed.`
        : "Links copied.";
      showToast({
        color: warning ? "yellow" : "green",
        title: `${responses.length} presigned URLs copied`,
        message: warning ? `${base}\n${warning}` : base,
        autoClose: TOAST_DURATIONS.infoLong,
      });
    } catch (e) {
      showToast({
        color: "red",
        title: "Copy failed",
        message: e instanceof Error ? e.message : "unknown error",
        autoClose: TOAST_DURATIONS.error,
      });
    } finally {
      bulkCopyingRef.current = false;
      setBulkCopying(false);
    }
  };

  const [previewState, setPreviewState] = useState<{
    filename: string;
    url: string;
    size: number;
  } | null>(null);

  const handlePreview = (name: string) => {
    const fileEntry = items.find((f) => f.name === name);
    if (!fileEntry || fileEntry.is_directory) return;
    const fullPath = joinPath(pathFromUrl, name);
    setPreviewState({
      filename: name,
      url: buildDownloadUrl(bucket, roleId, fullPath),
      size: fileEntry.size,
    });
  };

  const requestDelete = (names: string[]) => {
    pendingDelete.current = names;
    setConfirmOpen(true);
  };

  const confirmDelete = async () => {
    const names = pendingDelete.current;
    setConfirmOpen(false);
    if (names.length === 0) return;

    const showProgress = names.length > 1;
    let notifId: string | null = null;
    let success = 0;
    let failed = 0;
    // Cancel flag lives in a closure ref so the in-flight loop can
    // observe a click on the Cancel button without React re-renders
    // (the notification rerenders directly via notifications.update).
    const cancelRef = { cancelled: false };
    const onCancel = () => {
      cancelRef.cancelled = true;
    };

    const renderProgress = (started: number, currentName: string | null) => {
      if (!showProgress || notifId === null) return;
      notifications.update({
        id: notifId,
        message: (
          <BulkDeleteProgress
            started={started}
            total={names.length}
            currentName={currentName}
            onCancel={onCancel}
          />
        ),
        autoClose: false,
        withCloseButton: false,
        loading: true,
      });
    };

    if (showProgress) {
      notifId = notifications.show({
        message: (
          <BulkDeleteProgress
            started={0}
            total={names.length}
            currentName={names[0]}
            onCancel={onCancel}
          />
        ),
        autoClose: false,
        withCloseButton: false,
        loading: true,
      });
    }

    for (let i = 0; i < names.length; i++) {
      if (cancelRef.cancelled) break;
      const name = names[i];
      renderProgress(i, name);
      const fileEntry = items.find((f) => f.name === name);
      const fullPath = fileEntry?.is_directory
        ? joinPath(pathFromUrl, name) + "/"
        : joinPath(pathFromUrl, name);
      try {
        // Call deleteFile directly instead of useDelete().mutateAsync so the
        // batch doesn't push N copies of useMutation's "pending → success"
        // state transitions through React — each one was triggering a full
        // FileBrowser rerender on the open folder's table. The final
        // invalidation below refetches the file list ONCE after the batch.
        await deleteFile(bucket, roleId, fullPath);
        success++;
      } catch (e) {
        failed++;
        showToast({
          color: "red",
          message: `Failed to delete ${name}: ${e instanceof Error ? e.message : "unknown error"}`,
          autoClose: TOAST_DURATIONS.error,
        });
      }
    }

    if (showProgress && notifId !== null) {
      notifications.hide(notifId);
    }
    // Single invalidation after the batch. Runs for batches of one too —
    // earlier this was guarded by `if (showProgress)` (multi-file only),
    // which left single-file deletes with no cache refresh: the file
    // would actually delete on the backend but the row stayed on screen
    // until the user reloaded the page.
    queryClient.invalidateQueries({
      queryKey: filesQueryKey(bucket, roleId, pathFromUrl),
    });
    queryClient.invalidateQueries({
      queryKey: fileSearchFolderKey(bucket, roleId, pathFromUrl),
    });
    if (cancelRef.cancelled) {
      const remaining = names.length - success - failed;
      showToast({
        color: "yellow",
        message: `Bulk delete cancelled. Deleted ${success} of ${names.length}; ${remaining} skipped.`,
        autoClose: TOAST_DURATIONS.success,
      });
    } else if (success > 0) {
      showToast({
        color: "green",
        message: `Deleted ${success} item${success === 1 ? "" : "s"}${failed > 0 ? ` (${failed} failed)` : ""}`,
        autoClose: TOAST_DURATIONS.success,
      });
    }
    clearSelection();
  };

  // Visible-order names — shift-select range is computed against this list
  // (after sort + filter) so the highlighted range matches what the user sees.
  const orderedNames = useMemo(
    () => filteredItems.map((f) => f.name),
    [filteredItems],
  );
  const toggleSelect = (name: string, shiftKey: boolean) => {
    handleToggleSelect(name, shiftKey, orderedNames);
  };
  const toggleSelectAll = () => {
    handleToggleAll(orderedNames);
  };

  const handleLoadMore = useCallback(() => {
    loadMore().catch((e) =>
      showToast({
        color: "red",
        title: "Couldn't load more files",
        message: getErrorMessage(e),
        autoClose: TOAST_DURATIONS.error,
      }),
    );
  }, [loadMore]);

  // Auto-load the next chunk during lazy infinite scroll. In folder mode it's
  // paused while a client-side filter is active (the "Search '<term>' on server"
  // affordance is the explicit path there); in server-search mode it stays on so
  // the prefix results paginate. Never while a fetch is already in flight.
  const autoLoadEnabled =
    lazyLoadingEnabled &&
    truncated &&
    !isFetchingNextPage &&
    (serverSearchActive || !debouncedQuery);

  // Bottom-of-list "Load more" button, shown only when lazy-loading is OFF and
  // more objects remain. With lazy on, the near-end sentinel auto-loads on
  // scroll (except while a client-side filter is active), so a manual bottom button would never get a chance to be useful;
  // with lazy off, the header buttons were the only affordance — forcing a
  // scroll back to the top to fetch the next chunk. (The list is non-empty in
  // the table/grid branches — the empty case short-circuits above.)
  const showLoadMoreFooter = !lazyLoadingEnabled && truncated;

  const handleUpload = useCallback(
    async (files: FileWithRelativePath[]) => {
      const maxFileSize = me.data?.max_file_size;
      const items: UploadProgressItem[] = files.map((f) => ({
        name: f.file.name,
        status: "pending",
      }));

      // Single AbortController for the whole batch. Cancel button triggers
      // abort() which both stops the in-flight XHR (via signal) AND sets
      // signal.aborted=true so the loop bails before starting the next file.
      const controller = new AbortController();
      const cancel = () => controller.abort();

      // Hold the latest snapshot so the cancel button can show a sensible
      // final-state toast (otherwise the toast keeps re-rendering with stale
      // "uploading" status after the abort).
      const updated = [...items];

      const renderToast = () => {
        notifications.update({
          id: notifId,
          message: <UploadProgress items={updated} onCancel={cancel} />,
          autoClose: false,
          withCloseButton: false,
        });
      };

      const notifId = notifications.show({
        message: <UploadProgress items={items} onCancel={cancel} />,
        autoClose: false,
        withCloseButton: false,
      });

      for (let i = 0; i < files.length; i++) {
        // Cancel-aware loop guard. Once the user clicks cancel, mark every
        // remaining file as "cancelled" so the summary tells them what was
        // skipped, rather than leaving them as forever-"pending".
        if (controller.signal.aborted) {
          for (let j = i; j < files.length; j++) {
            updated[j] = { ...updated[j], status: "cancelled" };
          }
          break;
        }

        const item = files[i];

        // Pre-flight size check — skip the server round-trip for files we
        // already know will be rejected. The backend enforces the same limit
        // (streaming check in upload route), but doing it client-side first
        // means the user sees "doc.zip is 419 MB, limit is 100 MB" instead of
        // a generic 400 after the file has streamed up. Without this, batches
        // with one oversize file in the middle just silently skip it and the
        // user has no way to tell which file failed.
        //
        // Use formatBytes (binary KiB/MiB/GiB labeled as KB/MB/GB) so the size
        // shown here matches what the file table elsewhere in the UI shows for
        // the same file — consistency across the app beats decimal correctness.
        if (maxFileSize !== undefined && item.file.size > maxFileSize) {
          updated[i] = {
            ...updated[i],
            status: "error",
            error: `File is ${formatBytes(item.file.size)}, limit is ${formatBytes(maxFileSize)}`,
          };
          renderToast();
          continue;
        }

        updated[i] = { ...updated[i], status: "uploading", progress: 0 };
        renderToast();
        try {
          const key = pathFromUrl
            ? `${pathFromUrl}/${item.relativePath}`
            : item.relativePath;
          await uploadMutation.mutateAsync({
            bucket,
            role: roleId,
            key,
            file: item.file,
            currentPath: pathFromUrl,
            // Suppress per-file query invalidation; we invalidate ONCE after
            // the batch (see below). Without this, every successful file
            // triggered a listFiles refetch, and `isFetching` flipped the
            // FileBrowser into the loader between files — a flicker
            // (loader → table → loader → table…) while uploads streamed in.
            // Same fix as bulk-delete (commit b8543a1).
            skipInvalidation: true,
            signal: controller.signal,
            onProgress: (percent) => {
              // Throttle by skipping no-op updates — every progress event would
              // otherwise trigger a Mantine notifications re-render.
              if (updated[i].progress === percent) return;
              updated[i] = { ...updated[i], progress: percent };
              renderToast();
            },
          });
          updated[i] = { ...updated[i], status: "done", progress: 100 };
        } catch (e) {
          // Abort isn't a real failure — it's a user action. Distinguish so
          // the summary doesn't shout "ERROR" at the user who clicked cancel.
          const isAbort = e instanceof DOMException && e.name === "AbortError";
          // Use getErrorMessage so the backend's `detail` field is surfaced
          // (e.g. "File size exceeds maximum allowed size of 400MB") instead
          // of the generic `xhr.statusText` ("Internal Server Error" /
          // "Bad Request") that ApiError.message defaults to. The structured
          // `{detail: {code, message}}` shape from Phase 6a error-handling is
          // handled by the same helper.
          updated[i] = {
            ...updated[i],
            status: isAbort ? "cancelled" : "error",
            error: isAbort ? undefined : getErrorMessage(e),
          };
        }
        renderToast();
      }

      // Single invalidation after the batch — useUpload.skipInvalidation was
      // true inside the loop, so the open-folder file list only refetches
      // ONCE here instead of once per uploaded file. Skip the refetch
      // entirely if no file actually landed (every upload failed, or the
      // user cancelled before the first one succeeded) — nothing changed
      // server-side, so the GET would just return the same list.
      const anyUploaded = updated.some((u) => u.status === "done");
      if (anyUploaded) {
        queryClient.invalidateQueries({
          queryKey: filesQueryKey(bucket, roleId, pathFromUrl),
        });
        queryClient.invalidateQueries({
          queryKey: fileSearchFolderKey(bucket, roleId, pathFromUrl),
        });
      }

      // Final summary toast — `UploadSummary` surfaces failed filenames + their
      // error messages so a 223/224 batch tells the user WHICH file failed.
      // Successful batches dismiss quickly (the file table updates on success,
      // which is the real confirmation); failed / cancelled batches stay
      // longer so the user has time to read the failed list.
      const allDone = updated.every((u) => u.status === "done");
      const hasErrors = updated.some((u) => u.status === "error");
      const wasCancelled = updated.some((u) => u.status === "cancelled");
      const autoCloseMs = allDone
        ? TOAST_DURATIONS.success
        : TOAST_DURATIONS.error;
      notifications.update({
        id: notifId,
        message: <UploadSummary items={updated} autoCloseMs={autoCloseMs} />,
        color: allDone
          ? "green"
          : wasCancelled && !hasErrors
            ? "gray"
            : "yellow",
        autoClose: autoCloseMs,
        withCloseButton: true,
        // Override Mantine's baked-in body clipping. Without these, the
        // notification root's `align-items: center` + `overflow: hidden` on
        // the description body would cut the headline off the top and the
        // last list row off the bottom of a tall failed-files summary. We
        // want the message to render in full and let the inner scroll-area
        // (UploadSummary's maxHeight container) be the only clipping point.
        styles: {
          root: { alignItems: "stretch" },
          body: { overflow: "visible" },
          description: { overflow: "visible", textOverflow: "clip" },
        },
      });
    },
    [
      bucket,
      roleId,
      pathFromUrl,
      uploadMutation,
      queryClient,
      me.data?.max_file_size,
    ],
  );

  // Both upload buttons gate on the same dismissed-hint flag:
  //   - First click (any button): open the hint modal that teaches drag-drop.
  //     The folder mode keeps the dismiss checkbox unchecked (deliberate
  //     confirmation step, matches vanilla); the files mode pre-checks it
  //     (high-frequency action, single dismiss is enough).
  //   - Subsequent clicks (flag set): skip the modal, open the picker.
  // Drag-drop bypasses the modal entirely — the user already knows about
  // drag-drop if they're using it.
  const handleUploadClick = () => {
    if (hasDismissedFolderUploadHint()) {
      fileInputRef.current?.click();
    } else {
      setUploadHint({ open: true, mode: "files" });
    }
  };

  const handleUploadFolderClick = () => {
    if (hasDismissedFolderUploadHint()) {
      folderInputRef.current?.click();
    } else {
      setUploadHint({ open: true, mode: "folder" });
    }
  };

  const handleHintProceed = () => {
    const mode = uploadHint.mode;
    setUploadHint({ open: false, mode });
    // Wait a tick before opening the native picker so the modal's close
    // animation isn't competing with the file dialog for focus. setTimeout(0)
    // is enough — the Modal exit animation continues in parallel but the
    // picker has the user gesture context it needs to open.
    setTimeout(() => {
      if (mode === "folder") folderInputRef.current?.click();
      else fileInputRef.current?.click();
    }, 0);
  };

  const handleFileInput = (e: React.ChangeEvent<HTMLInputElement>) => {
    const fileList = e.target.files;
    if (fileList && fileList.length > 0) {
      // Plain-file input has no folder semantics — wrap each File as a
      // top-level FileWithRelativePath (relativePath = file.name).
      const items: FileWithRelativePath[] = Array.from(fileList).map(
        (file) => ({
          file,
          relativePath: file.name,
        }),
      );
      handleUpload(items);
    }
    e.target.value = "";
  };

  const handleFolderInput = (e: React.ChangeEvent<HTMLInputElement>) => {
    const fileList = e.target.files;
    if (fileList && fileList.length > 0) {
      const items = filesFromFolderInput(fileList);
      if (items.length > 0) handleUpload(items);
    }
    e.target.value = "";
  };

  return (
    <>
      <div className={classes.container}>
        <div className={classes.toolbar}>
          <BucketPageHeader
            bucket={bucket}
            roleId={roleId}
            path={pathFromUrl}
            objectCount={items.length}
            truncated={truncated}
          />
          <FileBrowserHeader
            searchQuery={searchQuery}
            onSearchChange={(q) => {
              setSearchQuery(q);
              clearSelection();
              if (serverSearchActive && q.trim() === "") exitServerSearch();
            }}
            mode={mode}
            onModeChange={setMode}
            onUploadClick={handleUploadClick}
            onUploadFolderClick={handleUploadFolderClick}
            truncated={truncated}
            isLoadingMore={isFetchingNextPage}
            onLoadMore={handleLoadMore}
            onLoadAll={() =>
              loadAll().catch((e) =>
                showToast({
                  color: "red",
                  title: "Couldn't load all files",
                  message: getErrorMessage(e),
                  autoClose: TOAST_DURATIONS.error,
                }),
              )
            }
          />
          <input
            type="file"
            ref={fileInputRef}
            onChange={handleFileInput}
            multiple
            style={{ display: "none" }}
          />
          <input
            type="file"
            ref={folderInputRef}
            onChange={handleFolderInput}
            multiple
            {...({ webkitdirectory: "" } as Record<string, string>)}
            style={{ display: "none" }}
          />
          {!serverSearchActive && debouncedQuery && truncated && (
            <Group gap="xs" align="center">
              <Text size="xs" c="dimmed">
                Filtering {items.length} loaded items.
              </Text>
              <Anchor
                size="xs"
                component="button"
                type="button"
                onClick={() => enterServerSearch(debouncedQuery)}
              >
                Search "{debouncedQuery.trim()}" on server (starts-with)
              </Anchor>
            </Group>
          )}
          {serverSearchActive && (
            <Group gap="xs" align="center">
              <Text size="xs" c="dimmed">
                Server search (starts-with, case-sensitive):
              </Text>
              <Badge
                variant="light"
                rightSection={
                  <CloseButton
                    size="xs"
                    aria-label="Exit server search"
                    onClick={exitServerSearch}
                  />
                }
              >
                {serverSearchTerm}
              </Badge>
            </Group>
          )}
        </div>

        {/* Loader / error / empty / list ALL render inside the scroll
            container so the scroll element stays mounted and measured across
            folder navigations. Early-returning a full-page loader/error BEFORE
            this container (the previous approach) unmounted the scroll element;
            when data then arrived, the freshly-mounted virtualizer measured a
            0-height element in its first frame and rendered nothing — the
            "folder looks empty until you leave and come back" glitch. Keeping
            the container mounted means the virtualizer always reads an
            already-laid-out, correctly-sized scroll element.

            Cold-load: spinner only when we have NO data (DelayedLoader still
            debounces 500ms so a fast fetch never flashes). Background refetches
            keep the table on screen. A non-continuation error blanks to the
            error state; a continuation (loadMore/loadAll) failure keeps the
            loaded table (handled by the `!isFetchNextPageError` guard) and
            surfaces as a toast. */}
        <div className={classes.scrollArea} ref={scrollRef}>
          {isFetching && items.length === 0 ? (
            <DelayedLoader label="Loading files…" />
          ) : error && !isFetchNextPageError ? (
            <QueryErrorState error={error} title="Couldn't load files" />
          ) : filteredItems.length === 0 ? (
            <FileBrowserEmptyState
              message={
                serverSearchActive
                  ? `No items start with "${serverSearchTerm}" here.`
                  : undefined
              }
            />
          ) : mode === "table" ? (
            <>
              <FileTable
                files={filteredItems}
                selected={selected}
                onToggleSelect={toggleSelect}
                onToggleSelectAll={toggleSelectAll}
                onNavigate={navigateToFolder}
                onDownload={handleDownload}
                onCopyUrl={handleCopyUrl}
                onCopyUrlWithTtl={handleCopyUrl}
                defaultTtl={presignedDefaultTtl}
                maxTtl={presignedMaxTtl}
                onPreview={handlePreview}
                onDelete={(name) => requestDelete([name])}
                scrollRef={scrollRef}
                autoLoadEnabled={autoLoadEnabled}
                onLoadMore={handleLoadMore}
              />
              {showLoadMoreFooter && (
                <FileBrowserLoadMoreFooter
                  loading={isFetchingNextPage}
                  onLoadMore={handleLoadMore}
                />
              )}
            </>
          ) : (
            <>
              <FileGrid
                files={filteredItems}
                selected={selected}
                onToggleSelect={toggleSelect}
                onNavigate={navigateToFolder}
                onDownload={handleDownload}
                onCopyUrl={handleCopyUrl}
                onCopyUrlWithTtl={handleCopyUrl}
                defaultTtl={presignedDefaultTtl}
                maxTtl={presignedMaxTtl}
                onPreview={handlePreview}
                onDelete={(name) => requestDelete([name])}
                bucket={bucket}
                roleId={roleId}
                path={pathFromUrl}
                scrollRef={scrollRef}
                autoLoadEnabled={autoLoadEnabled}
                onLoadMore={handleLoadMore}
              />
              {showLoadMoreFooter && (
                <FileBrowserLoadMoreFooter
                  loading={isFetchingNextPage}
                  onLoadMore={handleLoadMore}
                />
              )}
            </>
          )}
        </div>

        <ScrollToTopButton scrollRef={scrollRef} />
      </div>

      <UploadDropZone currentPath={pathFromUrl} onDrop={handleUpload} active />
      <FolderUploadHintModal
        opened={uploadHint.open}
        mode={uploadHint.mode}
        onClose={() => setUploadHint((prev) => ({ ...prev, open: false }))}
        onProceed={handleHintProceed}
      />
      <ConfirmDeleteModal
        opened={confirmOpen}
        onClose={() => setConfirmOpen(false)}
        onConfirm={confirmDelete}
        items={pendingDelete.current}
        loading={deleteMutation.isPending}
      />
      {previewState && (
        <PreviewModal
          opened={!!previewState}
          onClose={() => setPreviewState(null)}
          filename={previewState.filename}
          url={previewState.url}
          size={previewState.size}
        />
      )}
      {/* Contextual bulk-action bar — sibling of the modals, OUTSIDE the
          virtualized scroll container. Portals to the body via Affix; appears
          only while something is selected (see BulkActionBar). */}
      <BulkActionBar
        count={selected.size}
        onClear={clearSelection}
        onCopyUrls={handleBulkCopyUrl}
        onDelete={() => requestDelete(Array.from(selected))}
        disableDeletion={disableDeletion}
        defaultTtl={presignedDefaultTtl}
        maxTtl={presignedMaxTtl}
        busy={bulkCopying}
      />
    </>
  );
}
