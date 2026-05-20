import { useEffect, useState } from "react";
import { Alert, Anchor, Image, Stack } from "@mantine/core";
import { AlertTriangle } from "lucide-react";

interface ImagePreviewProps {
  url: string;
  alt: string;
}

export function ImagePreview({ url, alt }: ImagePreviewProps) {
  const [failed, setFailed] = useState(false);

  useEffect(() => {
    setFailed(false);
  }, [url]);

  if (failed) {
    return (
      <Stack gap="sm" align="center">
        <Alert color="red" icon={<AlertTriangle size={16} />}>
          Couldn't load this image. The file may be corrupted, in an unsupported format, or unreachable.
        </Alert>
        <Anchor href={url} download>
          Download
        </Anchor>
      </Stack>
    );
  }

  return (
    <Image
      src={url}
      alt={alt}
      onError={() => setFailed(true)}
      // fit="contain" so portrait / panoramic images render in full —
      // Mantine's <Image> defaults to object-fit: cover, which combined
      // with mah="70vh" was cropping the long axis of any non-4:3 image.
      // The user expectation in a preview modal is "see the whole thing",
      // not "see the centre slice".
      fit="contain"
      maw="100%"
      mah="70vh"
      display="block"
      mx="auto"
    />
  );
}
