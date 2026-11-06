// Content rules for user-supplied text (board messages and display names).
//
// The board is the enforcement point: anyone can run their own agent and Person
// Server, so it must not trust either to have checked anything. The agent and PS
// apply the same rules only so people get an error before they approve a post.
//
// Rules: plain text only. HTML is stripped, links are refused, invisible/control
// characters are removed, and a short list of explicit terms is refused. A word
// list can't catch everything (misspellings, other languages), so the board also
// renders posts strictly as text and sends a CSP that blocks third-party content.

export const MAX_MESSAGE = 280;
export const MAX_NAME = 40;

// Control characters, zero-width characters and bidi overrides (used to hide or
// visually reorder text). Newlines and tabs are kept.
const INVISIBLE = /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F-\u009F­​-‏‪-‮⁠-⁯﻿]/g;

// Anything that looks like a link: schemes, www., or a domain with a common TLD.
const LINK_PATTERNS = [
  /\b[a-z][a-z0-9+.-]*:\/\//i, // http://, https://, ftp://, ...
  /\b(?:javascript|data|vbscript|file|mailto):/i,
  /\bwww\./i,
  /\b[a-z0-9-]+(?:\.[a-z0-9-]+)*\.(?:com|net|org|io|co|me|ly|gg|tv|xyz|info|biz|app|dev|site|online|link|click|top|club|live|shop|store|pics|pic|cam|tube|porn|sex|xxx|adult|onion|ru|cn|tk|ml|ga|cf|uk|de|fr|jp|in|br|au|ca|us|eu|to|cc|ws|vip|fun|lol|art)(?![a-z0-9-])/i,
];

// Explicit terms, matched as whole words after normalization.
const BLOCKED_TERMS = [
  'porn', 'porno', 'pornhub', 'xxx', 'nsfw', 'nude', 'nudes', 'naked', 'sex', 'sexy', 'hentai', 'onlyfans',
  'fuck', 'fucking', 'fck', 'fuk', 'fucker', 'motherfucker', 'shit', 'cunt', 'cock', 'dick', 'pussy', 'tits', 'boobs', 'cum', 'blowjob', 'anal', 'milf', 'slut', 'whore',
  'nigger', 'nigga', 'faggot', 'fag', 'retard', 'kike', 'spic', 'chink',
];
const BLOCKED = new RegExp(`(?:^|[^a-z0-9])(?:${BLOCKED_TERMS.join('|')})(?:$|[^a-z0-9])`, 'i');

/** Strip HTML and invisible characters, normalize whitespace. Never returns markup. */
export function toPlainText(input, max) {
  let s = String(input ?? '').normalize('NFKC');
  s = s.replace(/<!--[\s\S]*?(?:-->|$)/g, ' '); // comments
  s = s.replace(/<\/?[a-z!?][^>]*>?/gi, ' '); // tags, including unterminated ones
  s = s.replace(/[<>]/g, ''); // stray angle brackets
  s = s.replace(INVISIBLE, '');
  s = s.replace(/\r\n?/g, '\n').replace(/[ \t]+/g, ' ').replace(/ *\n */g, '\n').replace(/\n{3,}/g, '\n\n');
  s = s.trim();
  return max ? s.slice(0, max).trim() : s;
}

export const containsLink = (s) => LINK_PATTERNS.some((re) => re.test(s));

// Also catch terms hidden with separators or leetspeak ("p.o.r.n", "p0rn").
const LEET = { 0: 'o', 1: 'i', 3: 'e', 4: 'a', 5: 's', 7: 't', '@': 'a', $: 's' };
function blocked(s) {
  if (BLOCKED.test(s)) return true;
  const deleeted = s.toLowerCase().replace(/[013457@$]/g, (c) => LEET[c]);
  if (BLOCKED.test(deleeted)) return true;
  const squashed = deleeted.replace(/(?<=\b\w)[^a-z0-9\s]+(?=\w\b)|(?<=\w)[._*-]+(?=\w)/g, '');
  return BLOCKED.test(squashed);
}

/**
 * Check a board message. Returns { ok: true, text } with the cleaned text, or
 * { ok: false, error } with a reason suitable for showing to the person.
 */
export function checkMessage(input) {
  const text = toPlainText(input);
  if (!text) return { ok: false, error: 'The message is empty (HTML is removed, plain text only).' };
  if (text.length > MAX_MESSAGE) return { ok: false, error: `Keep it to ${MAX_MESSAGE} characters.` };
  if (containsLink(text)) return { ok: false, error: 'Links aren\'t allowed on the board. Plain text only.' };
  if (blocked(text)) return { ok: false, error: 'That message contains language the board doesn\'t allow.' };
  return { ok: true, text };
}

/** Clean a display name. Never fails: unusable names become "Anonymous". */
export function cleanName(input) {
  const name = toPlainText(input, MAX_NAME).replace(/\n/g, ' ');
  if (!name || containsLink(name) || blocked(name)) return 'Anonymous';
  return name;
}
