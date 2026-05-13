import { useEffect, useState } from "react";
import { Alert, Anchor, Stack } from "@mantine/core";
import { AlertTriangle } from "lucide-react";

interface VideoPreviewProps {
  url: string;
}

export function VideoPreview({ url }: VideoPreviewProps) {
  const [failed, setFailed] = useState(false);

  useEffect(() => {
    setFailed(false);
  }, [url]);

  if (failed) {
    return (
      <Stack gap="sm" align="center">
        <Alert color="red" icon={<AlertTriangle size={16} />}>
          Couldn't load this video. The file may be corrupted, in an unsupported format, or
          unreachable.
        </Alert>
        <Anchor href={url} download>
          Download
        </Anchor>
      </Stack>
    );
  }

  return (
    <video
      src={url}
      controls
      onError={() => setFailed(true)}
      style={{ maxWidth: "100%", maxHeight: "70vh", display: "block", margin: "0 auto" }}
    />
  );
}
