import { useEffect, useState } from "react";
import { Center, Stack, Text } from "@mantine/core";
import { Upload } from "lucide-react";

interface UploadDropZoneProps {
  currentPath: string;
  onDrop: (files: File[]) => void;
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
      const files = Array.from(e.dataTransfer?.files ?? []);
      if (files.length > 0) onDrop(files);
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
