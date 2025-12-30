/**
 * Report Generator
 *
 * Core orchestration for report generation.
 */

import * as fs from 'fs';
import { gatherReportData } from './queries';
import { renderMarkdown } from './markdown';
import type { ReportOptions, GenerateReportResult, ReportData } from './types';
import { debug } from '../debug';

/**
 * Generate engagement report
 */
export async function generateReport(
  engagementId: string,
  options: ReportOptions
): Promise<GenerateReportResult> {
  debug.ipc('generateReport called', { engagementId, format: options.format });

  try {
    // Gather all data
    const data = await gatherReportData(engagementId);

    if (!data.engagement) {
      return { success: false, error: 'Engagement not found' };
    }

    // Generate content based on format
    let content: string;
    let extension: string;

    if (options.format === 'json') {
      content = JSON.stringify(data, null, 2);
      extension = 'json';
    } else {
      content = renderMarkdown(data, options);
      extension = 'md';
    }

    // Write to file if path provided
    if (options.outputPath) {
      const outputPath = options.outputPath.endsWith(`.${extension}`)
        ? options.outputPath
        : `${options.outputPath}.${extension}`;

      fs.writeFileSync(outputPath, content, 'utf-8');
      debug.ipc('Report written', { outputPath, size: content.length });

      return { success: true, outputPath, content };
    }

    // Return content only
    return { success: true, content };
  } catch (error) {
    debug.error('Report generation failed', error);
    return { success: false, error: String(error) };
  }
}

export type { ReportData, ReportOptions, GenerateReportResult };
