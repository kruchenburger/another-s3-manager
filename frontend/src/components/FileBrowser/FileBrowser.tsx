import { useMemo, useRef, useState, useCallback } from "react";
import { Center, Loader, Stack } from "@mantine/core";
import { notifications } from "@mantine/notifications";
import { useNavigate, useParams } from "react-router-dom";
import { useFiles } from "@/features/files/hooks/useFiles";
import { useDelete } from "@/features/files/hooks/useDelete";
import { useUpload } from "@/features/files/hooks/useUpload";
import { buildDownloadUrl, getPresignedDownloadUrl } from "@/features/files/api/filesApi";
import { useMe } from "@/features/auth/hooks/useMe";
import { useDisplayMode } from "@/hooks/useDisplayMode";
import { joinPath, decodePath } from "@/utils/pathUtils";
import { ConfirmDeleteModal } from "@/components/Confirm/ConfirmDeleteModal";
import { PreviewModal } from "@/components/Preview/PreviewModal";
import { UploadDropZone } from "@/components/Upload/UploadDropZone";
import { UploadProgress, type UploadProgressItem } from "@/components/Upload/UploadProgress";
import { FileBrowserHeader } from "./FileBrowserHeader";
import { FileTable } from "./FileTable";
import { FileGrid } from "./FileGrid";
import { FileBrowserEmptyState } from "./FileBrowserEmptyState";

export function FileBrowser() {
  const params = useParams<{ roleId: string; bucket: string; "*": string }>();
  const roleId = decodeURIComponent(params.roleId ?? "");
  const bucket = decodeURIComponent(params.bucket ?? "");
  const pathFromUrl = decodePath(params["*"] ?? "");
  const navigate = useNavigate();

  const { data, isLoading } = useFiles(bucket, roleId, pathFromUrl);
  const deleteMutation = useDelete();
  const uploadMutation = useUpload();
  const { mode, setMode } = useDisplayMode(roleId, bucket);
  const me = useMe();
  const disableDeletion = me.data?.disable_deletion ?? false;

  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [searchQuery, setSearchQuery] = useState("");
  const [confirmOpen, setConfirmOpen] = useState(false);
  const pendingDelete = useRef<string[]>([]);
  const fileInputRef = useRef<HTMLInputElement>(null);

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
    navigate(`/r/${encodeURIComponent(roleId)}/b/${encodeURIComponent(bucket)}/p/${encoded}`);
  };

  const handleDownload = (name: string) => {
    const fullPath = joinPath(pathFromUrl, name);
    window.location.href = buildDownloadUrl(bucket, roleId, fullPath);
  };

  const formatExpiry = (iso: string): string => {
    // Local time, hours+minutes only — `02:14 PM` is more useful than the full ISO.
    const d = new Date(iso);
    return d.toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit" });
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
      notifications.show({
        color: "green",
        title: "Presigned URL copied",
        message: `${name} — anyone with this link can download it until ${formatExpiry(expires_at)} (expires in 1 hour). No login needed.`,
        autoClose: 6000,
      });
    } catch (e) {
      notifications.show({
        color: "red",
        title: "Copy failed",
        message: e instanceof Error ? e.message : "unknown error",
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
      notifications.show({
        color: "green",
        title: `${responses.length} presigned URLs copied`,
        message: expiry
          ? `Anyone with these links can download until ${formatExpiry(expiry)} (expires in 1 hour). No login needed.`
          : "Anyone with these links can download for 1 hour. No login needed.",
        autoClose: 6000,
      });
    } catch (e) {
      notifications.show({
        color: "red",
        title: "Copy failed",
        message: e instanceof Error ? e.message : "unknown error",
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
    let success = 0;
    for (const name of names) {
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
        notifications.show({
          color: "red",
          message: `Failed to delete ${name}: ${e instanceof Error ? e.message : "unknown error"}`,
        });
      }
    }
    if (success > 0) {
      notifications.show({ color: "green", message: `Deleted ${success} item${success === 1 ? "" : "s"}` });
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
    async (files: File[]) => {
      const items: UploadProgressItem[] = files.map((f) => ({ name: f.name, status: "pending" }));

      const notifId = notifications.show({
        message: <UploadProgress items={items} />,
        autoClose: false,
        withCloseButton: false,
      });

      const updated = [...items];
      for (let i = 0; i < files.length; i++) {
        const file = files[i];
        updated[i] = { ...updated[i], status: "uploading" };
        notifications.update({
          id: notifId,
          message: <UploadProgress items={updated} />,
          autoClose: false,
          withCloseButton: false,
        });
        try {
          const key = pathFromUrl ? `${pathFromUrl}/${file.name}` : file.name;
          await uploadMutation.mutateAsync({
            bucket,
            role: roleId,
            key,
            file,
            currentPath: pathFromUrl,
          });
          updated[i] = { ...updated[i], status: "done" };
        } catch (e) {
          updated[i] = {
            ...updated[i],
            status: "error",
            error: e instanceof Error ? e.message : "unknown error",
          };
        }
        notifications.update({
          id: notifId,
          message: <UploadProgress items={updated} />,
          autoClose: false,
          withCloseButton: false,
        });
      }

      // Final summary toast
      const allDone = updated.every((u) => u.status === "done");
      const doneCount = updated.filter((u) => u.status === "done").length;
      notifications.update({
        id: notifId,
        message: allDone
          ? `Uploaded ${updated.length} file${updated.length === 1 ? "" : "s"}`
          : `${doneCount}/${updated.length} files uploaded`,
        color: allDone ? "green" : "yellow",
        autoClose: 5000,
        withCloseButton: true,
      });
    },
    [bucket, roleId, pathFromUrl, uploadMutation],
  );

  const handleUploadClick = () => {
    fileInputRef.current?.click();
  };

  const handleFileInput = (e: React.ChangeEvent<HTMLInputElement>) => {
    const files = Array.from(e.target.files ?? []);
    if (files.length > 0) handleUpload(files);
    e.target.value = "";
  };

  if (isLoading) {
    return (
      <Center py="xl">
        <Loader />
      </Center>
    );
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
      <Stack gap="md" data-tour="file-list">
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
