import { useEffect, useState } from "react";
import { Center, Loader, ScrollArea, Text } from "@mantine/core";

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
      .then((r) => {
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        return r.text();
      })
      .then((text) => {
        setContent(text);
        setLoading(false);
      })
      .catch((e) => {
        setError(e.message);
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
