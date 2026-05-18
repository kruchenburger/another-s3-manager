import { useEffect, useState } from "react";
import { Center, Stack, Text } from "@mantine/core";
import { Upload } from "lucide-react";
import {
  type FileWithRelativePath,
  expandDirectoryEntries,
} from "@/utils/folderUpload";

interface UploadDropZoneProps {
  currentPath: string;
  onDrop: (files: FileWithRelativePath[]) => void;
  /** Whether to actually attach window listeners. False during drawer/modal mode. */
  active?: boolean;
}

export function UploadDropZone({ currentPath, onDrop, active = true }: UploadDropZoneProps) {
  const [isDragging, setIsDragging] = useState(false);
  // Counter tracks nested dragenter/dragleave events to avoid flickering
  const [, setCounter] = useState(0);

  useEffect(() => {
    if (!active) return;

    const handleDragEnter = (e: DragEvent) => {
      if (!e.dataTransfer?.types.includes("Files")) return;
      e.preventDefault();
      setCounter((c) => {
        if (c === 0) setIsDragging(true);
        return c + 1;
      });
    };

    const handleDragLeave = (e: DragEvent) => {
      // dragleave with relatedTarget=null means the cursor left the browser
      // window entirely. Force-reset the counter so the overlay doesn't get
      // stuck if the user cancels a drag by leaving the window.
      if (e.relatedTarget === null) {
        setCounter(0);
        setIsDragging(false);
        return;
      }
      setCounter((c) => {
        const next = Math.max(0, c - 1);
        if (next === 0) setIsDragging(false);
        return next;
      });
    };

    const handleDragOver = (e: DragEvent) => {
      if (e.dataTransfer?.types.includes("Files")) {
        e.preventDefault();
      }
    };

    const handleDrop = (e: DragEvent) => {
      e.preventDefault();
      setIsDragging(false);
      setCounter(0);
      if (!e.dataTransfer) return;

      // Prefer `items + webkitGetAsEntry` so dropped folders are walked
      // recursively. Fall back to `files` for browsers/contexts where
      // webkitGetAsEntry is missing — they can't drop folders anyway.
      const items = Array.from(e.dataTransfer.items);
      const hasEntryApi = items.some(
        (item) => typeof item.webkitGetAsEntry === "function",
      );

      if (hasEntryApi) {
        // Asynchronous walker — fire-and-forget the promise; the onDrop callback
        // is invoked once the walk completes. We deliberately do NOT await here
        // because the handler is a DOM event listener; instead the consumer
        // receives the resolved file list when ready.
        expandDirectoryEntries(items).then((files) => {
          if (files.length > 0) onDrop(files);
        });
        return;
      }

      // Legacy fallback: flat FileList only. Wrap each File so the consumer's
      // signature stays uniform (relativePath === file.name for loose files).
      const flat = Array.from(e.dataTransfer.files);
      if (flat.length > 0) {
        onDrop(
          flat.map((file) => ({ file, relativePath: file.name })),
        );
      }
    };

    window.addEventListener("dragenter", handleDragEnter);
    window.addEventListener("dragleave", handleDragLeave);
    window.addEventListener("dragover", handleDragOver);
    window.addEventListener("drop", handleDrop);

    return () => {
      window.removeEventListener("dragenter", handleDragEnter);
      window.removeEventListener("dragleave", handleDragLeave);
      window.removeEventListener("dragover", handleDragOver);
      window.removeEventListener("drop", handleDrop);
    };
  }, [active, onDrop]);

  if (!isDragging) return null;

  return (
    <Center
      style={{
        position: "fixed",
        top: 0,
        left: 0,
        right: 0,
        bottom: 0,
        zIndex: 1000,
        background: "rgba(255, 193, 7, 0.15)",
        backdropFilter: "blur(8px)",
        border: "4px dashed var(--mantine-color-amber-6)",
        pointerEvents: "none",
      }}
    >
      <Stack align="center" gap="xs">
        <Upload size={64} color="var(--mantine-color-amber-6)" />
        <Text size="xl" fw={600}>
          Drop here to upload
        </Text>
        <Text c="dimmed">to /{currentPath || "(root)"}/</Text>
      </Stack>
    </Center>
  );
}
