import { Finding } from './extractFindings';
import { escapeMarkdownText, isAllowlistedRelativePath } from './markdownText';

const ICON_PREFIX = '<img src="https://raw.githubusercontent.com/Abdullah-Schahin/icons/';

function severityCell(severity: string): string {
  if (severity.startsWith(ICON_PREFIX) && !severity.includes('|') && !/[\r\n]/.test(severity)) {
    return severity;
  }
  return escapeMarkdownText(severity);
}

function locationCell(file: string, line: number, branch: string): string {
  const safeLine = typeof line === 'number' && Number.isInteger(line) && line >= 0 ? line : null;
  if (safeLine !== null && isAllowlistedRelativePath(branch) && isAllowlistedRelativePath(file)) {
    const base = file.slice(file.lastIndexOf('/') + 1);
    return `[${base}#L${safeLine}](../blob/${branch}/${file}#L${safeLine})`;
  }
  return escapeMarkdownText(`${file}#L${safeLine === null ? '' : safeLine}`);
}

export function formatSummaryComment(findings: Finding[], sarifData?: any, titleName?: string): string {
  const grouped: Record<string, Finding[]> = { error: [], warning: [], note: [] };
  for (const f of findings) {
    if (grouped[f.level]) grouped[f.level].push(f);
  }
  const headRef = process.env.GITHUB_HEAD_REF;
  const branch = headRef ? headRef : 'main';
  const driverName = sarifData?.runs?.[0]?.tool?.driver?.name;
  const driver = escapeMarkdownText(typeof driverName === 'string' && driverName ? driverName : 'Unknown Tool');
  const title = escapeMarkdownText(titleName || 'Security');
  const legend = `
<details>

<summary><strong>Legend: Severity Levels</strong></summary>

| Icon | Severity |
|:------:|----------|
| <img src=\"https://raw.githubusercontent.com/Abdullah-Schahin/icons/main/critical.svg\" alt=\"error\" width=\"18\" /> | CRITICAL / HIGH   |
| <img src=\"https://raw.githubusercontent.com/Abdullah-Schahin/icons/main/medium.svg\" alt=\"warning\" width=\"18\" /> | MEDIUM |
| <img src=\"https://raw.githubusercontent.com/Abdullah-Schahin/icons/main/low.svg\" alt=\"note\" width=\"18\" /> | LOW    |

</details>
`;
  const header =
    `# 🛡️ ${title} Findings Summary 🛡️\n` +
    `<details>\n<summary><strong>Details</strong></summary>\n\n` +
    `- Scanner: \`${driver}\`\n` +
    `- Total Findings: \`${findings.length}\`\n` +
    `- Source: SARIF\n` +
    `</details>\n\n` +
    legend + '\n';
  const tableHeader = '| Severity | Location | Rule ID | Message |\n|:--:|---------|---------|---------|\n';
  const rows = [
    ...(['error', 'warning', 'note'] as const).flatMap(level =>
      grouped[level].map(f =>
        `| ${severityCell(f.severity)} | ${locationCell(f.file, f.line, branch)} | ${escapeMarkdownText(f.rule_id)} | ${escapeMarkdownText(f.message_text)} |`
      )
    )
  ];
  return header + tableHeader + rows.join('\n') + '\n\n';
}
