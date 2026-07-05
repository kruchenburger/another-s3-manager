import { useEffect, useState } from "react";
import { Alert, Anchor, Center, Loader, ScrollArea, Stack } from "@mantine/core";
import { AlertTriangle } from "lucide-react";
import { ApiError, getErrorMessage } from "@/utils/apiError";

interface TextPreviewProps {
  url: string;
  size: number;
}

const MAX_SIZE = 5 * 1024 * 1024; // 5MB

type LoadState =
  | { status: "loading" }
  | { status: "ready"; content: string }
  | { status: "failed"; message: string };

export function TextPreview({ url, size }: TextPreviewProps) {
  const [state, setState] = useState<LoadState>({ status: "loading" });

  useEffect(() => {
    let cancelled = false;
    if (size > MAX_SIZE) {
      setState({
        status: "failed",
        message: `File too large for preview (${(size / 1024 / 1024).toFixed(1)} MB > 5 MB). Download to view.`,
      });
      return;
    }
    setState({ status: "loading" });
    fetch(url, { credentials: "include" })
      .then(async (r) => {
        if (cancelled) return;
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
        if (cancelled || text === undefined) return;
        setState({ status: "ready", content: text });
      })
      .catch((e) => {
        if (cancelled) return;
        setState({ status: "failed", message: getErrorMessage(e) });
      });
    return () => {
      cancelled = true;
    };
  }, [url, size]);

  if (state.status === "loading") {
    return (
      <Center py="xl">
        <Loader />
      </Center>
    );
  }

  if (state.status === "failed") {
    return (
      <Stack gap="sm" align="center">
        <Alert color="red" icon={<AlertTriangle size={16} />}>
          Couldn't load this text file. {state.message}
        </Alert>
        <Anchor href={url} download>
          Download
        </Anchor>
      </Stack>
    );
  }

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
        {state.content}
      </pre>
    </ScrollArea>
  );
}
