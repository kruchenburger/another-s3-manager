import { EmptyState } from "@/components/EmptyState/EmptyState";

export function FileBrowserEmptyState() {
  return (
    <EmptyState
      title="This folder is empty"
      description="Drop files here or click Upload to get started."
    />
  );
}
