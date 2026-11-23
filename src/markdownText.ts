/**
 * SARIF message text, rule ids, and tool names are plain strings. They are
 * escaped before being placed in a Markdown comment so they stay plain text.
 * Location links are built only from relative paths whose segments are
 * [A-Za-z0-9._-]+, with no empty, ".", or ".." segment.
 */

const LINE_BREAK = /[\0\u0008\u000B\u000C\u000E-\u001F\u007F\u0085\u2028\u2029\r\n]/g;
const INVISIBLE = /[\u00AD\u180E\u200B-\u200F\u202A-\u202E\u2060-\u2064\u2066-\u206F\uFEFF]/g;
const PATH_SEGMENT = /^[A-Za-z0-9._-]+$/;

export function escapeMarkdownText(value: string): string {
  return value
    .normalize('NFKC')
    .replace(INVISIBLE, '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/\\/g, '\\\\')
    .replace(/\|/g, '\\|')
    .replace(/`/g, "'")
    .replace(/\[/g, '&#91;')
    .replace(/\]/g, '&#93;')
    .replace(/\(/g, '&#40;')
    .replace(/\)/g, '&#41;')
    .replace(LINE_BREAK, ' ')
    .replace(/@/g, '@ ')
    .replace(/([a-z][a-z0-9+.-]*:)\/\//gi, '$1 //')
    .replace(/\bwww\./gi, 'www[.]');
}

export function isAllowlistedRelativePath(value: string): boolean {
  if (value.length === 0) return false;
  return value.split('/').every((segment) => segment !== '.' && segment !== '..' && PATH_SEGMENT.test(segment));
}

export function markdownCommentMarker(name: string): string {
  const safe = escapeMarkdownText(name).replace(/[<>]/g, ' ');
  return `<!-- SARIFCourier:${safe} -->`;
}
