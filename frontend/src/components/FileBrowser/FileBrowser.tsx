import { useMemo, useRef, useState, useCallback } from "react";
import { Center, Loader, Stack } from "@mantine/core";
import { notifications } from "@mantine/notifications";
import { useNavigate, useParams } from "react-router-dom";
import { useFiles } from "@/features/files/hooks/useFiles";
import { useDelete } from "@/features/files/hooks/useDelete";
import { useUpload } from "@/features/files/hooks/useUpload";
import { buildDownloadUrl } from "@/features/files/api/filesApi";
import { useDisplayMode } from "@/hooks/useDisplayMode";
import { joinPath, decodePath } from "@/utils/pathUtils";
import { ConfirmDeleteModal } from "@/components/Confirm/ConfirmDeleteModal";
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

  const handleCopyUrl = async (name: string) => {
    const fullPath = joinPath(pathFromUrl, name);
    const url = window.location.origin + buildDownloadUrl(bucket, roleId, fullPath);
    try {
      await navigator.clipboard.writeText(url);
      notifications.show({ color: "green", message: `Copied URL for ${name}` });
    } catch {
      notifications.show({ color: "red", message: "Failed to copy URL" });
    }
  };

  const handleBulkCopyUrl = async () => {
    const urls = Array.from(selected)
      .map((name) => window.location.origin + buildDownloadUrl(bucket, roleId, joinPath(pathFromUrl, name)))
      .join("\n");
    try {
      await navigator.clipboard.writeText(urls);
      notifications.show({ color: "green", message: `Copied ${selected.size} URLs` });
    } catch {
      notifications.show({ color: "red", message: "Failed to copy URLs" });
    }
  };

  const handlePreview = (_name: string) => {
    notifications.show({ color: "yellow", message: "Preview coming in next task" });
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
    </>
  );
}
