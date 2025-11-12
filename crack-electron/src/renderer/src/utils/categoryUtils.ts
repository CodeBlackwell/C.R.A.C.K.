import { CheatsheetListItem } from '../types/cheatsheet';

/**
 * Derive category from cheatsheet ID and tags
 * Based on ID prefixes and tag patterns
 */
export function deriveCategory(sheet: CheatsheetListItem): string {
  const id = sheet.id.toLowerCase();

  // Check ID prefixes
  if (id.startsWith('ad-')) return 'ACTIVE DIRECTORY';
  if (id.startsWith('amsi-')) return 'AMSI';
  if (id.startsWith('metasploit-')) return 'METASPLOIT FRAMEWORK';
  if (id.includes('password') || id.includes('hash') || id.includes('crack')) {
    return 'PASSWORD ATTACKS';
  }
  if (id.includes('shellcode')) return 'SHELLCODE';
  if (id.includes('signature')) return 'SIGNATURES';
  if (id.includes('ssh')) return 'SSH TECHNIQUES';
  if (id.includes('uac')) return 'UAC';
  if (id.includes('log-poison') || id.includes('rfi') || id.includes('lfi') || id.includes('xss') || id.includes('sqli')) {
    return 'WEB TECHNIQUES';
  }
  if (id.includes('windows') || id.includes('port-forward')) return 'WINDOWS TECHNIQUES';

  // Default category
  return 'OTHER';
}

/**
 * Group cheatsheets by category
 */
export function groupByCategory(sheets: CheatsheetListItem[]): Map<string, CheatsheetListItem[]> {
  const grouped = new Map<string, CheatsheetListItem[]>();

  sheets.forEach(sheet => {
    const category = deriveCategory(sheet);
    sheet.category = category; // Add category to sheet object

    if (!grouped.has(category)) {
      grouped.set(category, []);
    }
    grouped.get(category)!.push(sheet);
  });

  // Sort categories by priority
  const categoryOrder = [
    'ACTIVE DIRECTORY',
    'METASPLOIT FRAMEWORK',
    'PASSWORD ATTACKS',
    'WEB TECHNIQUES',
    'WINDOWS TECHNIQUES',
    'SSH TECHNIQUES',
    'AMSI',
    'UAC',
    'SHELLCODE',
    'SIGNATURES',
    'OTHER',
  ];

  const sortedMap = new Map<string, CheatsheetListItem[]>();
  categoryOrder.forEach(cat => {
    if (grouped.has(cat)) {
      sortedMap.set(cat, grouped.get(cat)!);
    }
  });

  // Add any remaining categories not in the order list
  grouped.forEach((sheets, category) => {
    if (!sortedMap.has(category)) {
      sortedMap.set(category, sheets);
    }
  });

  return sortedMap;
}
