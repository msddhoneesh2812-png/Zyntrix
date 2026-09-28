import React, { Component, type ErrorInfo, type ReactNode } from 'react';
import { AlertTriangle, RefreshCw } from 'lucide-react';

interface ErrorBoundaryProps {
  children: ReactNode;
}

interface ErrorBoundaryState {
  hasError: boolean;
  error: Error | null;
}

class ErrorBoundary extends Component<ErrorBoundaryProps, ErrorBoundaryState> {
  constructor(props: ErrorBoundaryProps) {
    super(props);
    this.state = { hasError: false, error: null };
  }

  static getDerivedStateFromError(error: Error): ErrorBoundaryState {
    return { hasError: true, error };
  }

  componentDidCatch(error: Error, errorInfo: ErrorInfo): void {
    console.error('ErrorBoundary caught:', error, errorInfo);
  }

  handleRetry = (): void => {
    this.setState({ hasError: false, error: null });
  };

  render(): ReactNode {
    if (this.state.hasError) {
      return (
        <div className="flex-1 flex items-center justify-center bg-slate-50 p-6">
          <div className="glass-panel p-10 max-w-lg w-full text-center">
            <div className="mx-auto w-16 h-16 rounded-full bg-cyber-critical/20 flex items-center justify-center mb-6">
              <AlertTriangle size={32} className="text-cyber-critical" />
            </div>
            <h2 className="text-2xl font-bold text-slate-900 mb-3">
              Something went wrong
            </h2>
            <p className="text-slate-600 mb-6 text-sm leading-relaxed">
              An unexpected error occurred in this section. The rest of the application
              is unaffected. You can try reloading this view.
            </p>
            {this.state.error && (
              <pre className="text-left bg-slate-50 border border-slate-200 rounded-lg p-4 mb-6 text-xs text-slate-600 font-mono overflow-auto max-h-32">
                {this.state.error.message}
              </pre>
            )}
            <button
              onClick={this.handleRetry}
              className="btn-primary inline-flex items-center gap-2"
              aria-label="Retry loading this section"
            >
              <RefreshCw size={16} />
              Try Again
            </button>
          </div>
        </div>
      );
    }

    return this.props.children;
  }
}

export default ErrorBoundary;
