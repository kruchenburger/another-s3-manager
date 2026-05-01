interface PdfPreviewProps {
  url: string;
}

export function PdfPreview({ url }: PdfPreviewProps) {
  return (
    <iframe
      src={url}
      title="PDF preview"
      style={{ width: "100%", height: "70vh", border: "none" }}
    />
  );
}
