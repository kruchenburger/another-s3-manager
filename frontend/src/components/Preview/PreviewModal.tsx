import { Modal } from "@mantine/core";
import { ImagePreview } from "./ImagePreview";
import { VideoPreview } from "./VideoPreview";
import { PdfPreview } from "./PdfPreview";
import { TextPreview } from "./TextPreview";

interface PreviewModalProps {
  opened: boolean;
  onClose: () => void;
  filename: string;
  url: string;
  size: number;
}

function detectType(filename: string): "image" | "video" | "pdf" | "text" | null {
  const ext = filename.toLowerCase().split(".").pop() ?? "";
  if (["png", "jpg", "jpeg", "gif", "webp", "svg"].includes(ext)) return "image";
  if (["mp4", "webm", "mov"].includes(ext)) return "video";
  if (ext === "pdf") return "pdf";
  if (["txt", "json", "yaml", "yml", "log", "md"].includes(ext)) return "text";
  return null;
}

export function PreviewModal({ opened, onClose, filename, url, size }: PreviewModalProps) {
  const type = detectType(filename);

  return (
    <Modal opened={opened} onClose={onClose} title={filename} size="xl" centered>
      {type === "image" && <ImagePreview url={url} alt={filename} />}
      {type === "video" && <VideoPreview url={url} />}
      {type === "pdf" && <PdfPreview url={url} />}
      {type === "text" && <TextPreview url={url} size={size} />}
      {type === null && <p>This file type cannot be previewed. Download to view.</p>}
    </Modal>
  );
}
