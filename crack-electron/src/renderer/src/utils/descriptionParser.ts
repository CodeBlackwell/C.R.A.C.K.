/**
 * Description Parser Utility
 * Parses attack chain step descriptions into typed content blocks for styled rendering
 */

export type ContentBlockType =
  | 'major-header'      // ALL CAPS + colon (e.g., "PREREQUISITES CHECK:")
  | 'subsection-header' // Mixed case with parentheses or METHOD/STEP prefix
  | 'emphasis'          // OPSEC:, CRITICAL:, IMPORTANT:, NOTE:
  | 'success'           // SUCCESS:, EXPECTED: (positive context)
  | 'failure'           // FAILURE:, ERROR:, negative context
  | 'warning'           // WARNING:, CAUTION:
  | 'info'              // INFO:, TIP:, EXAM TIP:
  | 'command'           // Command line (single line)
  | 'code-block'        // Multi-line code block
  | 'list-item'         // List items (numbered or bulleted)
  | 'prose';            // Regular text

export interface ContentBlock {
  type: ContentBlockType;
  content: string;
  metadata?: {
    indent?: number;
    prefix?: string;  // For list items
    keyword?: string; // For emphasis/success/failure (the keyword itself)
  };
}

/**
 * Patterns for detecting content types
 */
const PATTERNS = {
  // Major headers: ALL CAPS followed by colon (must be at start of line)
  majorHeader: /^([A-Z][A-Z\s]{2,}[A-Z]):\s*/,

  // Subsection headers: METHOD N:, STEP N:, or text with parentheses:
  subsectionHeader: /^(METHOD \d+|STEP \d+|[A-Z][A-Za-z\s]+ \([^)]+\)):\s*/,

  // Emphasis keywords
  emphasis: /^(OPSEC|CRITICAL|IMPORTANT|NOTE|REMEMBER|KEY|EXAM TIP|TIP):\s*/i,

  // Success indicators
  success: /^(SUCCESS|EXPECTED|CONFIRMED|VALIDATED|WORKING):\s*/i,

  // Failure indicators
  failure: /^(FAILURE|ERROR|FAILED|PROBLEM|ISSUE|DENIED):\s*/i,

  // Warning indicators
  warning: /^(WARNING|CAUTION|ALERT|ATTENTION|DETECTION RISK):\s*/i,

  // Info indicators
  info: /^(INFO|EXPLANATION|BACKGROUND|THEORY|CONCEPT):\s*/i,

  // Command indicators (common command prefixes)
  command: /^(sudo |impacket-|crackmapexec |nmap |curl |wget |nc |python|python3 |bash |sh |cmd |powershell |net |certutil |for |cat |grep |echo |cd |ls |pwd |whoami |chmod |chown )/,

  // List items
  listNumbered: /^(\d+[\.\)]|\(\d+\))\s+/,
  listBulleted: /^([-•*])\s+/,

  // Code block markers (indented or common multi-line patterns)
  codeBlockStart: /^(```|    |\t)/,
};

/**
 * Parse description text into structured content blocks
 */
export function parseDescription(description: string): ContentBlock[] {
  if (!description) {
    return [];
  }

  const lines = description.split('\n');
  const blocks: ContentBlock[] = [];
  let currentCodeBlock: string[] | null = null;
  let currentProse: string[] | null = null;

  const flushProse = () => {
    if (currentProse && currentProse.length > 0) {
      blocks.push({
        type: 'prose',
        content: currentProse.join('\n').trim(),
      });
      currentProse = null;
    }
  };

  const flushCodeBlock = () => {
    if (currentCodeBlock && currentCodeBlock.length > 0) {
      blocks.push({
        type: 'code-block',
        content: currentCodeBlock.join('\n'),
      });
      currentCodeBlock = null;
    }
  };

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const trimmed = line.trim();

    // Skip empty lines (but preserve in code blocks)
    if (trimmed === '') {
      if (currentCodeBlock) {
        currentCodeBlock.push(line);
      } else if (currentProse) {
        currentProse.push('');
      }
      continue;
    }

    // Check if we're in a code block
    if (currentCodeBlock !== null) {
      // Check for code block end (```)
      if (trimmed === '```') {
        flushCodeBlock();
        continue;
      }
      // Continue collecting code block lines
      currentCodeBlock.push(line);
      continue;
    }

    // Check for code block start
    if (trimmed.startsWith('```')) {
      flushProse();
      currentCodeBlock = [];
      continue;
    }

    // Check for indented code (4 spaces or tab) - but not list continuation
    if ((line.startsWith('    ') || line.startsWith('\t')) && !PATTERNS.listNumbered.test(trimmed) && !PATTERNS.listBulleted.test(trimmed)) {
      flushProse();
      if (!currentCodeBlock) {
        currentCodeBlock = [];
      }
      currentCodeBlock.push(line);
      continue;
    }

    // If we had a code block and this line is not indented, flush it
    if (currentCodeBlock) {
      flushCodeBlock();
    }

    // Check for major headers
    const majorMatch = trimmed.match(PATTERNS.majorHeader);
    if (majorMatch) {
      flushProse();
      blocks.push({
        type: 'major-header',
        content: trimmed,
        metadata: { keyword: majorMatch[1] },
      });
      continue;
    }

    // Check for subsection headers
    const subsectionMatch = trimmed.match(PATTERNS.subsectionHeader);
    if (subsectionMatch) {
      flushProse();
      blocks.push({
        type: 'subsection-header',
        content: trimmed,
        metadata: { keyword: subsectionMatch[1] },
      });
      continue;
    }

    // Check for emphasis keywords
    const emphasisMatch = trimmed.match(PATTERNS.emphasis);
    if (emphasisMatch) {
      flushProse();
      blocks.push({
        type: 'emphasis',
        content: trimmed,
        metadata: { keyword: emphasisMatch[1] },
      });
      continue;
    }

    // Check for success indicators
    const successMatch = trimmed.match(PATTERNS.success);
    if (successMatch) {
      flushProse();
      blocks.push({
        type: 'success',
        content: trimmed,
        metadata: { keyword: successMatch[1] },
      });
      continue;
    }

    // Check for failure indicators
    const failureMatch = trimmed.match(PATTERNS.failure);
    if (failureMatch) {
      flushProse();
      blocks.push({
        type: 'failure',
        content: trimmed,
        metadata: { keyword: failureMatch[1] },
      });
      continue;
    }

    // Check for warning indicators
    const warningMatch = trimmed.match(PATTERNS.warning);
    if (warningMatch) {
      flushProse();
      blocks.push({
        type: 'warning',
        content: trimmed,
        metadata: { keyword: warningMatch[1] },
      });
      continue;
    }

    // Check for info indicators
    const infoMatch = trimmed.match(PATTERNS.info);
    if (infoMatch) {
      flushProse();
      blocks.push({
        type: 'info',
        content: trimmed,
        metadata: { keyword: infoMatch[1] },
      });
      continue;
    }

    // Check for numbered list items
    const numberedMatch = trimmed.match(PATTERNS.listNumbered);
    if (numberedMatch) {
      flushProse();
      blocks.push({
        type: 'list-item',
        content: trimmed.replace(PATTERNS.listNumbered, ''),
        metadata: { prefix: numberedMatch[1] },
      });
      continue;
    }

    // Check for bulleted list items
    const bulletMatch = trimmed.match(PATTERNS.listBulleted);
    if (bulletMatch) {
      flushProse();
      blocks.push({
        type: 'list-item',
        content: trimmed.replace(PATTERNS.listBulleted, ''),
        metadata: { prefix: bulletMatch[1] },
      });
      continue;
    }

    // Check for command lines
    if (PATTERNS.command.test(trimmed)) {
      flushProse();
      blocks.push({
        type: 'command',
        content: trimmed,
      });
      continue;
    }

    // Default: prose text
    if (!currentProse) {
      currentProse = [];
    }
    currentProse.push(line);
  }

  // Flush any remaining prose or code blocks
  flushProse();
  flushCodeBlock();

  return blocks;
}
