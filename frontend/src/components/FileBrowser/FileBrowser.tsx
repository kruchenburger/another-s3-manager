import { useMemo, useRef, useState, useCallback } from "react";
import { Center, Loader, Stack } from "@mantine/core";
import { notifications } from "@mantine/notifications";
import { useNavigate, useParams } from "react-router-dom";
import { useFiles } from "@/features/files/hooks/useFiles";
import { useDelete } from "@/features/files/hooks/useDelete";
import { useUpload } from "@/features/files/hooks/useUpload";
import {
  buildDownloadUrl,
  getPresignedDownloadUrl,
} from "@/features/files/api/filesApi";
import { useMe } from "@/features/auth/hooks/useMe";
import { useDisplayMode } from "@/hooks/useDisplayMode";
import { joinPath, decodePath } from "@/utils/pathUtils";
import { ApiError, getErrorMessage } from "@/utils/apiError";
import { formatBytes } from "@/utils/formatBytes";
import { formatTimeOfDay } from "@/utils/formatDate";
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
import { FileBrowserHeader } from "./FileBrowserHeader";
import { FileTable } from "./FileTable";
import { FileGrid } from "./FileGrid";
import { FileBrowserEmptyState } from "./FileBrowserEmptyState";
import { BulkDeleteProgress } from "@/components/FileBrowser/BulkDeleteProgress";
import { QueryErrorState } from "@/components/QueryErrorState/QueryErrorState";

export function FileBrowser() {
  const params = useParams<{ roleId: string; bucket: string; "*": string }>();
  const roleId = decodeURIComponent(params.roleId ?? "");
  const bucket = decodeURIComponent(params.bucket ?? "");
  const pathFromUrl = decodePath(params["*"] ?? "");
  const navigate = useNavigate();

  const { data, isLoading, error } = useFiles(bucket, roleId, pathFromUrl);
  const deleteMutation = useDelete();
  const uploadMutation = useUpload();
  const { mode, setMode } = useDisplayMode(roleId, bucket);
  const me = useMe();
  const disableDeletion = me.data?.disable_deletion ?? false;

  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [searchQuery, setSearchQuery] = useState("");
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

  const filteredFiles = useMemo(() => {
    if (!data?.files) return [];
    if (!searchQuery) return data.files;
    const q = searchQuery.toLowerCase();
    return data.files.filter((f) => f.name.toLowerCase().includes(q));
  }, [data?.files, searchQuery]);

  const navigateToFolder = (folderName: string) => {
    setSelected(new Set());
    setSearchQuery("");
    const next = joinPath(pathFromUrl, folderName);
    const encoded = next.split("/").map(encodeURIComponent).join("/");
    navigate(
      `/r/${encodeURIComponent(roleId)}/b/${encodeURIComponent(bucket)}/p/${encoded}`,
    );
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

  const handleCopyUrl = async (name: string) => {
    const fullPath = joinPath(pathFromUrl, name);
    try {
      const { url, expires_at } = await getPresignedDownloadUrl(
        bucket,
        roleId,
        fullPath,
      );
      await navigator.clipboard.writeText(url);
      showToast({
        color: "green",
        title: "Presigned URL copied",
        message: `${name} — anyone with this link can download it until ${formatTimeOfDay(expires_at)} (expires in 1 hour). No login needed.`,
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

  const handleBulkCopyUrl = async () => {
    const names = Array.from(selected);
    try {
      const responses = await Promise.all(
        names.map((name) =>
          getPresignedDownloadUrl(bucket, roleId, joinPath(pathFromUrl, name)),
        ),
      );
      const urls = responses.map((r) => r.url).join("\n");
      await navigator.clipboard.writeText(urls);
      // All URLs in a bulk copy share the same backend timestamp (same request batch).
      const expiry = responses[0]?.expires_at;
      showToast({
        color: "green",
        title: `${responses.length} presigned URLs copied`,
        message: expiry
          ? `Anyone with these links can download until ${formatTimeOfDay(expiry)} (expires in 1 hour). No login needed.`
          : "Anyone with these links can download for 1 hour. No login needed.",
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

  const [previewState, setPreviewState] = useState<{
    filename: string;
    url: string;
    size: number;
  } | null>(null);

  const handlePreview = (name: string) => {
    const fileEntry = data?.files.find((f) => f.name === name);
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
    const notifId = "bulk-delete-progress";
    let success = 0;
    let failed = 0;

    // Note: renderProgress() is called at the START of each iteration,
    // so "Deleting N of M: X" means X is IN-FLIGHT (not yet completed).
    // This is by design — the UI tracks initiated, not completed items.
    const renderProgress = (completed: number, currentName: string | null) => {
      if (!showProgress) return;
      notifications.update({
        id: notifId,
        message: (
          <BulkDeleteProgress
            completed={completed}
            total={names.length}
            currentName={currentName}
          />
        ),
        autoClose: false,
        withCloseButton: false,
        loading: completed < names.length,
      });
    };

    if (showProgress) {
      notifications.show({
        id: notifId,
        message: (
          <BulkDeleteProgress
            completed={0}
            total={names.length}
            currentName={names[0]}
          />
        ),
        autoClose: false,
        withCloseButton: false,
        loading: true,
      });
    }

    for (let i = 0; i < names.length; i++) {
      const name = names[i];
      renderProgress(i, name);
      const fileEntry = data?.files.find((f) => f.name === name);
      const fullPath = fileEntry?.is_directory
        ? joinPath(pathFromUrl, name) + "/"
        : joinPath(pathFromUrl, name);
      try {
        await deleteMutation.mutateAsync({
          bucket,
          role: roleId,
          path: fullPath,
          currentPath: pathFromUrl,
        });
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

    if (showProgress) {
      notifications.hide(notifId);
    }
    if (success > 0) {
      showToast({
        color: "green",
        message: `Deleted ${success} item${success === 1 ? "" : "s"}${failed > 0 ? ` (${failed} failed)` : ""}`,
        autoClose: TOAST_DURATIONS.success,
      });
    }
    setSelected(new Set());
  };

  const toggleSelect = (name: string) => {
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(name)) next.delete(name);
      else next.add(name);
      return next;
    });
  };

  const toggleSelectAll = () => {
    if (filteredFiles.every((f) => selected.has(f.name))) {
      setSelected(new Set());
    } else {
      setSelected(new Set(filteredFiles.map((f) => f.name)));
    }
  };

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
    [bucket, roleId, pathFromUrl, uploadMutation, me.data?.max_file_size],
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

  if (isLoading) {
    return (
      <Center py="xl">
        <Loader />
      </Center>
    );
  }

  // Stale-data + fresh-error race: TanStack Query may still hold cached `data`
  // while a concurrent refetch failed. Show the error state regardless of any
  // ghost data — without this guard the file table flashes the stale list.
  if (error) {
    return <QueryErrorState error={error} title="Couldn't load files" />;
  }

  return (
    <>
      <FileBrowserHeader
        bucket={bucket}
        roleId={roleId}
        path={pathFromUrl}
        searchQuery={searchQuery}
        onSearchChange={setSearchQuery}
        mode={mode}
        onModeChange={setMode}
        selectedCount={selected.size}
        onBulkDelete={() => requestDelete(Array.from(selected))}
        onBulkCopyUrl={handleBulkCopyUrl}
        onUploadClick={handleUploadClick}
        onUploadFolderClick={handleUploadFolderClick}
        disableDeletion={disableDeletion}
        objectCount={data?.files?.length ?? 0}
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
        // `webkitdirectory` is a non-standard attribute that React doesn't type;
        // pass it via spread to bypass the type check. All major browsers honor it
        // (Chrome, Firefox, Safari, Edge); the fallback is the drag-drop path which
        // works on browsers that don't support webkitdirectory inputs.
        {...({ webkitdirectory: "" } as Record<string, string>)}
        style={{ display: "none" }}
      />
      <Stack gap="md">
        {filteredFiles.length === 0 ? (
          <FileBrowserEmptyState />
        ) : mode === "table" ? (
          <FileTable
            files={filteredFiles}
            selected={selected}
            onToggleSelect={toggleSelect}
            onToggleSelectAll={toggleSelectAll}
            onNavigate={navigateToFolder}
            onDownload={handleDownload}
            onCopyUrl={handleCopyUrl}
            onPreview={handlePreview}
            onDelete={(name) => requestDelete([name])}
          />
        ) : (
          <FileGrid
            files={filteredFiles}
            selected={selected}
            onToggleSelect={toggleSelect}
            onNavigate={navigateToFolder}
            onDownload={handleDownload}
            onCopyUrl={handleCopyUrl}
            onPreview={handlePreview}
            onDelete={(name) => requestDelete([name])}
            bucket={bucket}
            roleId={roleId}
            path={pathFromUrl}
          />
        )}
      </Stack>
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
    </>
  );
}
