import { useEffect, useState } from "react";
import { Alert, Anchor, Center, Loader, Stack } from "@mantine/core";
import { AlertTriangle } from "lucide-react";
import { ApiError, getErrorMessage } from "@/utils/apiError";

interface PdfPreviewProps {
  url: string;
}

type PreflightState =
  | { status: "loading" }
  | { status: "ready" }
  | { status: "failed"; message: string };

export function PdfPreview({ url }: PdfPreviewProps) {
  const [state, setState] = useState<PreflightState>({ status: "loading" });

  useEffect(() => {
    let cancelled = false;
    setState({ status: "loading" });
    // <iframe onError> is unreliable cross-origin (blank page, no React event).
    // Pre-flight with HEAD so we can render a real Alert on permission/network errors.
    fetch(url, { method: "HEAD", credentials: "include" })
      .then(async (r) => {
        if (cancelled) return;
        if (!r.ok) {
          // HEAD response bodies are typically empty, but the boundary may still
          // return JSON for some endpoints — try anyway for a richer message.
          let body: unknown;
          try {
            body = await r.json();
          } catch {
            body = undefined;
          }
          throw new ApiError(r.status, r.statusText, body);
        }
        setState({ status: "ready" });
      })
      .catch((e) => {
        if (cancelled) return;
        setState({ status: "failed", message: getErrorMessage(e) });
      });
    return () => {
      cancelled = true;
    };
  }, [url]);

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
          Couldn't load this PDF. {state.message}
        </Alert>
        <Anchor href={url} download>
          Download
        </Anchor>
      </Stack>
    );
  }

  return (
    <iframe
      src={url}
      title="PDF preview"
      style={{ width: "100%", height: "70vh", border: "none" }}
    />
  );
}
