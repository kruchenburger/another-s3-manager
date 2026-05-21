import { SimpleGrid } from "@mantine/core";
import type { FileEntry } from "@/types/api";
import { FileCard } from "./FileCard";

interface FileGridProps {
  files: FileEntry[];
  selected: Set<string>;
  onToggleSelect: (name: string, shiftKey: boolean) => void;
  onNavigate: (name: string) => void;
  onDownload: (name: string) => void;
  onCopyUrl: (name: string) => void;
  onPreview: (name: string) => void;
  onDelete: (name: string) => void;
  // Forwarded to FileCard so each card can fetch its own presigned thumbnail URL.
  bucket: string;
  roleId: string;
  path: string;
}

export function FileGrid(props: FileGridProps) {
  return (
    <SimpleGrid cols={{ base: 2, sm: 3, md: 4, lg: 6 }} spacing="md">
      {props.files.map((file, i) => (
        <FileCard
          key={file.name}
          file={file}
          index={i}
          selected={props.selected.has(file.name)}
          onToggleSelect={props.onToggleSelect}
          onNavigate={props.onNavigate}
          onDownload={props.onDownload}
          onCopyUrl={props.onCopyUrl}
          onPreview={props.onPreview}
          onDelete={props.onDelete}
          bucket={props.bucket}
          roleId={props.roleId}
          path={props.path}
        />
      ))}
    </SimpleGrid>
  );
}
