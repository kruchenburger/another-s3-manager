import type { FileEntry, MoveItem, MoveRequest } from "@/types/api";
import { formatBytes } from "@/utils/formatBytes";

export const MOVE_EXPLANATION =
  "Object storage has no rename or move. ASM copies each object to the new location and then deletes the original. This moves {objects} objects ({size}).";
export const LARGE_MOVE_WARNING =
  "This can take a while; you can keep working — progress stays in the corner.";
export const MOVE_DISABLED =
  "Moving is disabled because deletion is disabled in the server config.";
export const INTERNAL_DRAG_TYPE = "application/x-as3m-keys";
export const exactJoin = (parent: string, name: string) =>
  parent ? `${parent}/${name}` : name;
export const itemIdentity = (item: MoveItem) =>
  JSON.stringify([item.path, item.kind]);
export const entryItem = (parent: string, entry: FileEntry): MoveItem => ({
  path: exactJoin(parent, entry.name),
  kind: entry.is_directory ? "folder" : "file",
});
export const entryIdentity = (parent: string, entry: FileEntry) =>
  itemIdentity(entryItem(parent, entry));
export function decodeIdentity(id: string): MoveItem {
  const [path, kind] = JSON.parse(id) as [string, MoveItem["kind"]];
  return { path, kind };
}
export const itemName = (item: MoveItem) =>
  item.path.slice(item.path.lastIndexOf("/") + 1);
export const itemParent = (item: MoveItem) =>
  item.path.slice(0, Math.max(0, item.path.lastIndexOf("/")));
export function validateName(name: string, parent?: string): string | null {
  // Python str.strip() includes NEL and excludes the JavaScript-only BOM.
  const stripped = name.replace(
    /^[\u0009-\u000d\u001c-\u0020\u0085\u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000]+|[\u0009-\u000d\u001c-\u0020\u0085\u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000]+$/gu,
    "",
  );
  if (
    !name ||
    Array.from(name).length > 255 ||
    name !== stripped ||
    name.includes("/") ||
    name === "." ||
    name === ".." ||
    /[\x00-\x1f\x7f]/.test(name)
  )
    return "Use 1–255 characters, without slashes, control characters or surrounding whitespace.";
  if (
    parent !== undefined &&
    new TextEncoder().encode(`${exactJoin(parent, name)}/`).length > 1024
  )
    return "The folder key exceeds 1024 UTF-8 bytes.";
  return null;
}
export function targetError(
  items: MoveItem[],
  destination: string,
): string | null {
  if (
    items.some(
      (item) =>
        item.kind === "folder" &&
        (destination === item.path || destination.startsWith(item.path + "/")),
    )
  )
    return "A folder cannot be moved into itself or a descendant.";
  if (
    items.some(
      (item) =>
        destination === itemParent(item) &&
        (!item.new_name || item.new_name === itemName(item)),
    )
  )
    return "Choose another folder or enter a different new name.";
  return null;
}
export function moveExplanation(objects: number, bytes: number) {
  return MOVE_EXPLANATION.replace("{objects}", String(objects)).replace(
    "{size}",
    formatBytes(bytes),
  );
}
export function newMoveAction(request: MoveRequest) {
  return {
    ...request,
    items: request.items.map((item) => ({ ...item })),
    operation_id: crypto.randomUUID(),
  };
}
