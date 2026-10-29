import { useRef, useState, type DragEvent, type HTMLAttributes } from "react";
import { useMediaQuery } from "@mantine/hooks";
import type { MoveItem, MoveRequest } from "@/types/api";
import {
  INTERNAL_DRAG_TYPE,
  itemIdentity,
  decodeIdentity,
  targetError,
} from "@/features/files/utils/folderOperations";
interface Payload {
  bucket: string;
  role: string;
  items: MoveItem[];
}
type DragProps = HTMLAttributes<HTMLElement> & { "data-move-target"?: string };
export interface InternalFileDrag {
  row: (item: MoveItem) => DragProps;
  target: (path: string) => DragProps;
}
export function useInternalFileDrag({
  bucket,
  role,
  selected,
  disabled,
  onDrop,
}: {
  bucket: string;
  role: string;
  // Retained for callers that provide visible rows; selection identities are authoritative.
  items?: MoveItem[];
  selected: Set<string>;
  disabled: boolean;
  onDrop: (request: MoveRequest) => void;
}): InternalFileDrag {
  const desktop = useMediaQuery(
    "(min-width: 48em) and (hover: hover) and (pointer: fine)",
    undefined,
    { getInitialValueInEffect: false },
  );
  const active = useRef<Payload | null>(null);
  const [dragging, setDragging] = useState<Payload | null>(null);
  const [hover, setHover] = useState<string | null>(null);
  const read = (event: DragEvent<HTMLElement>): Payload | null => {
    if (
      disabled ||
      !desktop ||
      !event.dataTransfer.types.includes(INTERNAL_DRAG_TYPE)
    )
      return null;
    try {
      const data: unknown = JSON.parse(
        event.dataTransfer.getData(INTERNAL_DRAG_TYPE),
      );
      if (!data || typeof data !== "object") return null;
      const p = data as Partial<Payload>;
      if (
        p.bucket !== bucket ||
        p.role !== role ||
        !Array.isArray(p.items) ||
        !p.items.length ||
        p.items.length > 1000 ||
        !p.items.every(
          (item) =>
            typeof item?.path === "string" &&
            item.path.length > 0 &&
            (item.kind === "file" || item.kind === "folder"),
        )
      )
        return null;
      return p as Payload;
    } catch {
      return null;
    }
  };
  const target = (path: string): DragProps => ({
    "data-move-target":
      hover === path && dragging
        ? targetError(dragging.items, path)
          ? "invalid"
          : "valid"
        : undefined,
    onDragOver: (event) => {
      if (
        disabled ||
        !desktop ||
        !event.dataTransfer.types.includes(INTERNAL_DRAG_TYPE)
      )
        return;
      const payload = active.current;
      const valid =
        payload?.bucket === bucket &&
        payload?.role === role &&
        !targetError(payload.items, path);
      event.preventDefault();
      event.stopPropagation();
      event.dataTransfer.dropEffect = valid ? "move" : "none";
      setHover(path);
    },
    onDragLeave: () => setHover(null),
    onDrop: (event) => {
      if (!event.dataTransfer.types.includes(INTERNAL_DRAG_TYPE)) return;
      event.preventDefault();
      event.stopPropagation();
      const payload = read(event);
      setHover(null);
      if (payload && !targetError(payload.items, path))
        onDrop({ items: payload.items, destination: path });
    },
  });
  return {
    target,
    row: (item) => ({
      ...(item.kind === "folder" ? target(item.path) : {}),
      draggable: !!desktop && !disabled,
      onDragStart: (event) => {
        if (!desktop || disabled) {
          event.preventDefault();
          return;
        }
        const chosen = selected.has(itemIdentity(item))
          ? Array.from(selected, decodeIdentity)
          : [item];
        const payload = { bucket, role, items: chosen };
        active.current = payload;
        setDragging(payload);
        event.dataTransfer.setData(INTERNAL_DRAG_TYPE, JSON.stringify(payload));
        event.dataTransfer.effectAllowed = "move";
      },
      onDragEnd: () => {
        active.current = null;
        setDragging(null);
        setHover(null);
      },
    }),
  };
}
