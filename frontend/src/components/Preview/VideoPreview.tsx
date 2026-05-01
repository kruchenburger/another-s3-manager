interface VideoPreviewProps {
  url: string;
}

export function VideoPreview({ url }: VideoPreviewProps) {
  return (
    <video
      src={url}
      controls
      style={{ maxWidth: "100%", maxHeight: "70vh", display: "block", margin: "0 auto" }}
    />
  );
}
