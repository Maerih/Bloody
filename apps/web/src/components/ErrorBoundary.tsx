import { Component, type ErrorInfo, type ReactNode } from "react";
import { ErrorState } from "./ErrorState";

interface Props {
  children: ReactNode;
  /** Changing this value resets the boundary (e.g. the current pathname). */
  resetKey?: string;
}
interface State {
  error: Error | null;
}

/** Contains rendering failures to the page that caused them; the shell stays usable. */
export class ErrorBoundary extends Component<Props, State> {
  override state: State = { error: null };

  static getDerivedStateFromError(error: Error): State {
    return { error };
  }

  override componentDidCatch(error: Error, info: ErrorInfo): void {
    // Surface in the browser console for support; no customer data is sent anywhere.
    console.error("Bloody UI error", error, info.componentStack);
  }

  override componentDidUpdate(prev: Props): void {
    if (prev.resetKey !== this.props.resetKey && this.state.error) this.setState({ error: null });
  }

  override render(): ReactNode {
    if (this.state.error) {
      return (
        <div className="rounded border border-line bg-surface shadow-card">
          <ErrorState error={this.state.error} title="This page failed to render" onRetry={() => this.setState({ error: null })} />
        </div>
      );
    }
    return this.props.children;
  }
}
