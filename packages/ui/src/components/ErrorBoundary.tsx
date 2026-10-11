import { Component, type ReactNode } from 'react';
import { EmptyState } from './EmptyState';

interface Props {
  children: ReactNode;
  /** When this changes (navigation), a failed page gets a fresh try. */
  resetKey: string;
}

interface State {
  error: Error | null;
}

/** One failing page must not blank the whole report. */
export class ErrorBoundary extends Component<Props, State> {
  override state: State = { error: null };

  static getDerivedStateFromError(error: Error): State {
    return { error };
  }

  override componentDidUpdate(previous: Props): void {
    if (previous.resetKey !== this.props.resetKey && this.state.error)
      this.setState({ error: null });
  }

  override render(): ReactNode {
    if (this.state.error) {
      return (
        <EmptyState
          name="UnableToLoad"
          title="This page could not be displayed"
          subtitle={`${this.state.error.message}. Open another section, or reload the file. Please report this on GitHub with the steps that led here.`}
        />
      );
    }
    return this.props.children;
  }
}
