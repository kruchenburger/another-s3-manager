import { EmptyState } from "@/components/EmptyState/EmptyState";

interface FileBrowserEmptyStateProps {
  message?: string;
}

export function FileBrowserEmptyState({ message }: FileBrowserEmptyStateProps) {
  return (
    <EmptyState
      title="This folder is empty"
      description={message ?? "Drop files here or click Upload to get started."}
    />
  );
}
