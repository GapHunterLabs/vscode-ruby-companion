/**
 * Pure line-based Ruby scanners -- no `vscode` dependency. Faithful
 * ports of 3 Gap Hunter Labs IntelliJ-family plugins
 * (ruby-shell-injection-companion, ruby-nethttp-reuse-companion,
 * ruby-gemfile-group-companion), all already plain-text/regex
 * scanners with zero PSI dependency in their originals. Combined
 * into one extension for the same reason as PHP Security Companion:
 * one listing with several rules fits VS Code's ecosystem better
 * than 3 near-identical tiny ones.
 */

export interface Hit {
  rule: string;
  line: number; // 1-based
  message: string;
}

/** Shell injection: system(/exec(/backticks/%x[] with #{} interpolation. */
export function scanShellInjection(text: string): Hit[] {
  const SYSTEM_OR_EXEC_CALL = /\b(system|exec)\s*\(\s*(["'])(?:[^"'\\]|\\.)*#\{/;
  const BACKTICK_CALL = /`[^`]*#\{/;
  const PERCENT_X_CALL = /%x[[(][^\])]*#\{/;

  const hits: Hit[] = [];
  text.split('\n').forEach((rawLine, index) => {
    if (rawLine.trimStart().startsWith('#')) return;

    const systemMatch = SYSTEM_OR_EXEC_CALL.exec(rawLine);
    if (systemMatch) {
      hits.push({ rule: 'shell-injection', line: index + 1, message: `Potential shell injection: '${systemMatch[1]}(' built with #{} interpolation.` });
    }
    if (BACKTICK_CALL.test(rawLine)) {
      hits.push({ rule: 'shell-injection', line: index + 1, message: 'Potential shell injection: backtick command built with #{} interpolation.' });
    }
    if (PERCENT_X_CALL.test(rawLine)) {
      hits.push({ rule: 'shell-injection', line: index + 1, message: 'Potential shell injection: %x[] command built with #{} interpolation.' });
    }
  });
  return hits;
}

const LOOP_HEADER = /\.(each|each_with_index|times|map|select|loop)\b.*\bdo\b\s*(\|[^|]*\|)?\s*$/;
const WHILE_FOR_HEADER = /^\s*(while|until|for)\b.*$/;
const BRACE_LOOP_HEADER = /\.(each|each_with_index|times|map|select)\b.*\{\s*(\|[^|]*\|)?\s*$/;
const BLOCK_END = /^\s*end\s*$/;
const OTHER_DO_BLOCK = /.*\bdo\b\s*(\|[^|]*\|)?\s*$/;
const NET_HTTP_CALL = /Net::HTTP\.(get_response|get|post)\(/;

/** Net::HTTP shorthand call (opens+closes a connection every call)
 * found inside a loop/iterator block. */
export function scanNetHttpInLoop(text: string): Hit[] {
  const hits: Hit[] = [];
  let loopDoDepth = 0;
  let otherDoDepth = 0;
  let braceDepth = 0;

  text.split('\n').forEach((rawLine, index) => {
    const trimmed = rawLine.trim();
    if (trimmed === '' || trimmed.startsWith('#')) return;

    if (loopDoDepth === 0 && braceDepth === 0 && (LOOP_HEADER.test(trimmed) || WHILE_FOR_HEADER.test(trimmed))) {
      loopDoDepth++;
      return;
    }
    if (loopDoDepth === 0 && braceDepth === 0 && BRACE_LOOP_HEADER.test(trimmed)) {
      braceDepth++;
      return;
    }
    if (loopDoDepth > 0 && braceDepth === 0 && OTHER_DO_BLOCK.test(trimmed)) {
      otherDoDepth++;
    } else if (loopDoDepth > 0 && braceDepth === 0 && otherDoDepth > 0 && BLOCK_END.test(trimmed)) {
      otherDoDepth--;
    } else if (loopDoDepth > 0 && braceDepth === 0 && otherDoDepth === 0 && BLOCK_END.test(trimmed)) {
      loopDoDepth--;
      return;
    } else if (braceDepth > 0) {
      const opens = (trimmed.match(/\{/g) ?? []).length;
      const closes = (trimmed.match(/\}/g) ?? []).length;
      braceDepth += opens - closes;
      if (braceDepth <= 0) {
        braceDepth = 0;
        return;
      }
    }

    if (loopDoDepth === 0 && braceDepth === 0) return;

    const match = NET_HTTP_CALL.exec(trimmed);
    if (!match) return;
    hits.push({
      rule: 'nethttp-per-iteration',
      line: index + 1,
      message: `Net::HTTP.${match[1]}(...) opens a new connection every call -- found inside a loop. Use Net::HTTP.start(...) to reuse one connection across iterations.`,
    });
  });
  return hits;
}

const GEM_LINE = /^gem\s+["']([\w.-]+)["']/;
const GROUP_BLOCK_START = /^group\s+.*\bdo\b\s*$/;
const OTHER_BLOCK_START = /.*\bdo\b(\s*\|[^|]*\|)?\s*$/;

const KNOWN_DEV_TEST_GEMS = new Set([
  'rspec', 'rspec-rails', 'minitest', 'rubocop', 'rubocop-rails', 'rubocop-rspec',
  'pry', 'pry-byebug', 'byebug', 'factory_bot', 'factory_bot_rails', 'capybara',
  'selenium-webdriver', 'simplecov', 'webmock', 'vcr', 'faker', 'shoulda-matchers',
  'database_cleaner', 'guard', 'guard-rspec', 'rerun', 'spring', 'brakeman',
  'bullet', 'letter_opener', 'annotate',
]);

/** A well-known dev/test gem declared at the Gemfile's top level
 * (not inside any group :development/:test block). */
export function scanGemfileGroups(text: string): Hit[] {
  const hits: Hit[] = [];
  let groupDepth = 0;
  let otherBlockDepth = 0;

  text.split('\n').forEach((rawLine, index) => {
    const trimmed = rawLine.trim();
    if (trimmed === '' || trimmed.startsWith('#')) return;

    if (GROUP_BLOCK_START.test(trimmed)) {
      groupDepth++;
      return;
    }
    if (groupDepth > 0 && OTHER_BLOCK_START.test(trimmed)) {
      groupDepth++;
      return;
    }
    if (groupDepth > 0 && BLOCK_END.test(trimmed)) {
      groupDepth--;
      return;
    }
    if (groupDepth === 0 && OTHER_BLOCK_START.test(trimmed)) {
      otherBlockDepth++;
      return;
    }
    if (groupDepth === 0 && otherBlockDepth > 0 && BLOCK_END.test(trimmed)) {
      otherBlockDepth--;
      return;
    }

    if (groupDepth > 0) return;

    const match = GEM_LINE.exec(trimmed);
    if (!match) return;
    const gemName = match[1];
    if (KNOWN_DEV_TEST_GEMS.has(gemName)) {
      hits.push({
        rule: 'ungrouped-dev-test-gem',
        line: index + 1,
        message: `'${gemName}' is a dev/test gem declared outside any group :development/:test block -- it will ship in every environment, including production.`,
      });
    }
  });
  return hits;
}
