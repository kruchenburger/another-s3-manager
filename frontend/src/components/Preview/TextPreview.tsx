import { useEffect, useState } from "react";
import { Center, Loader, ScrollArea, Text } from "@mantine/core";
import { ApiError, getErrorMessage } from "@/utils/apiError";

interface TextPreviewProps {
  url: string;
  size: number;
}

const MAX_SIZE = 5 * 1024 * 1024; // 5MB

export function TextPreview({ url, size }: TextPreviewProps) {
  const [content, setContent] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (size > MAX_SIZE) {
      setError(`File too large for preview (${(size / 1024 / 1024).toFixed(1)} MB > 5 MB). Download to view.`);
      setLoading(false);
      return;
    }
    setLoading(true);
    fetch(url, { credentials: "include" })
      .then(async (r) => {
        if (!r.ok) {
          let body: unknown;
          try {
            body = await r.json();
          } catch {
            body = undefined;
          }
          throw new ApiError(r.status, r.statusText, body);
        }
        return r.text();
      })
      .then((text) => {
        setContent(text);
        setLoading(false);
      })
      .catch((e) => {
        setError(getErrorMessage(e));
        setLoading(false);
      });
  }, [url, size]);

  if (loading) return <Center py="xl"><Loader /></Center>;
  if (error) return <Text c="red">{error}</Text>;

  return (
    <ScrollArea h="70vh">
      <pre style={{
        margin: 0,
        padding: 16,
        fontSize: 13,
        fontFamily: "var(--mantine-font-family-monospace)",
        whiteSpace: "pre-wrap",
        wordBreak: "break-word",
      }}>
        {content}
      </pre>
    </ScrollArea>
  );
}
