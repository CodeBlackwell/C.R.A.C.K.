/**
 * Report IPC Handlers
 *
 * Handles report generation requests from the renderer process.
 */

import { ipcMain, dialog } from 'electron';
import { generateReport } from '../report/generator';
import type { ReportOptions } from '../report/types';
import { debug } from '../debug';

/**
 * Register report IPC handlers
 */
export function registerReportHandlers(): void {
  debug.ipc('Registering report IPC handlers');

  // Generate report (returns content or writes to path)
  ipcMain.handle('report-generate', async (
    _,
    engagementId: string,
    options: ReportOptions
  ) => {
    debug.ipc('report-generate called', { engagementId, format: options.format });
    return generateReport(engagementId, options);
  });

  // Show save dialog and generate report
  ipcMain.handle('report-export', async (
    _,
    engagementId: string,
    options: Omit<ReportOptions, 'outputPath'>
  ) => {
    debug.ipc('report-export called', { engagementId, format: options.format });

    const extension = options.format === 'json' ? 'json' : 'md';
    const timestamp = new Date().toISOString().slice(0, 10);
    const defaultName = `engagement-report-${timestamp}.${extension}`;

    const result = await dialog.showSaveDialog({
      title: 'Export Engagement Report',
      defaultPath: defaultName,
      filters: [
        { name: options.format === 'json' ? 'JSON' : 'Markdown', extensions: [extension] },
        { name: 'All Files', extensions: ['*'] },
      ],
    });

    if (result.canceled || !result.filePath) {
      return { success: false, canceled: true };
    }

    return generateReport(engagementId, {
      ...options,
      outputPath: result.filePath,
    });
  });

  debug.ipc('Report IPC handlers registered');
}
