interface ImagePreviewProps {
  url: string;
  alt: string;
}

export function ImagePreview({ url, alt }: ImagePreviewProps) {
  return (
    <img
      src={url}
      alt={alt}
      style={{ maxWidth: "100%", maxHeight: "70vh", display: "block", margin: "0 auto" }}
    />
  );
}
