import { EmptyState } from "@/components/EmptyState/EmptyState";

export function HomePage() {
  return (
    <EmptyState
      title="Pick a role to get started"
      description="Your accessible roles and buckets are listed in the sidebar."
      burgerSize={96}
    />
  );
}
