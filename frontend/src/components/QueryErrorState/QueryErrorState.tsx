import type { ReactNode } from "react";
import { EmptyState } from "@/components/EmptyState/EmptyState";
import { getErrorMessage } from "@/utils/apiError";

interface QueryErrorStateProps {
  /** The error from a `useQuery` result. Caller already gated this on `error` truthy. */
  error: unknown;
  /** Title shown in the empty state, e.g. "Couldn't load files". */
  title: string;
  /** Optional CTA — e.g. an "Open admin to fix" button. */
  cta?: ReactNode;
}

export function QueryErrorState({ error, title, cta }: QueryErrorStateProps) {
  return (
    <EmptyState
      tone="warning"
      title={title}
      description={getErrorMessage(error)}
      cta={cta}
    />
  );
}
