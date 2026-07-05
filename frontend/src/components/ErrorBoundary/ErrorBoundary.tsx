import { Component, type ErrorInfo, type ReactNode } from "react";
import { ErrorFallback } from "@/components/ErrorBoundary/ErrorFallback";

interface ErrorBoundaryProps {
  children: ReactNode;
}

interface ErrorBoundaryState {
  error: Error | null;
}

// Class component because React still has no hook-based equivalent.
// Catches render-time errors only — async errors must be caught by TanStack Query.
export class ErrorBoundary extends Component<ErrorBoundaryProps, ErrorBoundaryState> {
  state: ErrorBoundaryState = { error: null };

  static getDerivedStateFromError(error: Error): ErrorBoundaryState {
    return { error };
  }

  componentDidCatch(error: Error, info: ErrorInfo): void {
    console.error("[ErrorBoundary]", error, info);
  }

  private handleReset = (): void => {
    // Full reload is the safest reset — clears any corrupted module state.
    window.location.reload();
  };

  render(): ReactNode {
    if (this.state.error) {
      return <ErrorFallback error={this.state.error} onReset={this.handleReset} />;
    }
    return this.props.children;
  }
}
