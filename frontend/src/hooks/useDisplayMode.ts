import { useCallback, useEffect, useState } from "react";

export type DisplayMode = "table" | "grid";

const KEY_PREFIX = "display:";

function storageKey(role: string, bucket: string): string {
  return `${KEY_PREFIX}${role}:${bucket}`;
}

export function useDisplayMode(role: string, bucket: string) {
  const [mode, setModeState] = useState<DisplayMode>(() => {
    if (typeof window === "undefined") return "table";
    const v = localStorage.getItem(storageKey(role, bucket));
    return v === "grid" ? "grid" : "table";
  });

  // Re-read storage when role/bucket changes
  useEffect(() => {
    const v = localStorage.getItem(storageKey(role, bucket));
    setModeState(v === "grid" ? "grid" : "table");
  }, [role, bucket]);

  const setMode = useCallback(
    (next: DisplayMode) => {
      localStorage.setItem(storageKey(role, bucket), next);
      setModeState(next);
    },
    [role, bucket],
  );

  return { mode, setMode };
}
