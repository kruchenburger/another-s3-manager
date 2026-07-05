import { Modal } from "@mantine/core";
import { useConfig } from "@/hooks/useConfig";
import { getPreviewType } from "@/utils/filePreview";
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

export function PreviewModal({ opened, onClose, filename, url, size }: PreviewModalProps) {
  const { data: config } = useConfig();
  const type = getPreviewType(filename, config?.auto_inline_extensions ?? []);

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
