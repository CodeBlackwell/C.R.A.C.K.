/**
 * useComponentLogger - React hook for component lifecycle logging
 *
 * Provides scoped logging methods and automatic lifecycle tracking.
 *
 * Usage:
 *   const logger = useComponentLogger('TargetSidebar');
 *   logger.logAction('Target added', { ip: '192.168.1.1' });
 *   logger.logUI('Panel expanded');
 */

import { useEffect, useRef, useCallback } from 'react';
import { log, LogCategory } from '@shared/electron/debug-renderer';

export interface ComponentLogger {
  /** Log a user action */
  logAction: (action: string, data?: unknown) => void;
  /** Log a UI state change */
  logUI: (change: string, data?: unknown) => void;
  /** Log a validation result */
  logValidation: (field: string, error: string, data?: unknown) => void;
  /** Log data loading */
  logData: (operation: string, data?: unknown) => void;
  /** Log an IPC call */
  logIPC: (channel: string, data?: unknown, correlationId?: string) => void;
  /** Log an error */
  logError: (message: string, error?: unknown) => void;
  /** Log focus event */
  logFocus: (element: string, focused: boolean) => void;
  /** Generate a correlation ID */
  generateCorrelationId: () => string;
}

/**
 * Hook that provides scoped logging methods for a component
 *
 * @param componentName - Name of the component for log prefixing
 * @param options - Optional configuration
 * @returns Logger methods scoped to this component
 */
export function useComponentLogger(
  componentName: string,
  options?: {
    /** Log component mount/unmount */
    logLifecycle?: boolean;
    /** Log render count */
    logRenders?: boolean;
  }
): ComponentLogger {
  const mountTime = useRef(Date.now());
  const renderCount = useRef(0);
  const { logLifecycle = true, logRenders = false } = options || {};

  // Track render count
  renderCount.current += 1;

  // Log lifecycle events
  useEffect(() => {
    if (logLifecycle) {
      log.lifecycle(`${componentName} mounted`, {
        renderCount: renderCount.current,
      });
    }

    return () => {
      if (logLifecycle) {
        const lifetime = Date.now() - mountTime.current;
        log.lifecycle(`${componentName} unmounted`, {
          lifetime_ms: lifetime,
          totalRenders: renderCount.current,
        });
      }
    };
  }, [componentName, logLifecycle]);

  // Log renders (if enabled)
  useEffect(() => {
    if (logRenders && renderCount.current > 1) {
      log.render(`${componentName} re-rendered`, {
        renderCount: renderCount.current,
      });
    }
  });

  // Scoped logging methods
  const logAction = useCallback(
    (action: string, data?: unknown) => {
      log.action(`${componentName}: ${action}`, data);
    },
    [componentName]
  );

  const logUI = useCallback(
    (change: string, data?: unknown) => {
      log.ui(`${componentName}: ${change}`, data);
    },
    [componentName]
  );

  const logValidation = useCallback(
    (field: string, error: string, data?: unknown) => {
      log.validation(`${componentName}: ${field}`, { error, ...data as object });
    },
    [componentName]
  );

  const logData = useCallback(
    (operation: string, data?: unknown) => {
      log.data(`${componentName}: ${operation}`, data);
    },
    [componentName]
  );

  const logIPC = useCallback(
    (channel: string, data?: unknown, correlationId?: string) => {
      log.ipc(`${componentName} -> ${channel}`, data, correlationId);
    },
    [componentName]
  );

  const logError = useCallback(
    (message: string, error?: unknown) => {
      log.error(LogCategory.ERROR, `${componentName}: ${message}`, error);
    },
    [componentName]
  );

  const logFocus = useCallback(
    (element: string, focused: boolean) => {
      log.focus(`${componentName}: ${element} ${focused ? 'focused' : 'blurred'}`);
    },
    [componentName]
  );

  const generateCorrelationId = useCallback(() => {
    return log.generateCorrelationId();
  }, []);

  return {
    logAction,
    logUI,
    logValidation,
    logData,
    logIPC,
    logError,
    logFocus,
    generateCorrelationId,
  };
}

export default useComponentLogger;
