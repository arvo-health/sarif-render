// src/convert.ts
import { extractFindings } from './extractFindings';
import { formatSummaryComment } from './formatSummaryComment';

export function convert(sarifContent: any, titleName?: string): string {
  return formatSummaryComment(extractFindings(sarifContent), sarifContent, titleName);
}
