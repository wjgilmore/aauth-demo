import { test } from 'node:test';
import assert from 'node:assert/strict';
import { checkMessage, cleanName, toPlainText } from './content.mjs';

test('HTML is stripped to plain text', () => {
  assert.equal(toPlainText('<b>hi</b> <script>alert(1)</script>there'), 'hi alert(1) there');
  assert.equal(toPlainText('<img src=x onerror=alert(1)>hello'), 'hello');
  assert.equal(toPlainText('<img src="x" onerror="alert(1)"'), '');
  assert.equal(toPlainText('a <!-- hidden --> b'), 'a b');
  assert.equal(toPlainText('1 < 2 and 3 > 2'), '1 2 and 3 2');
  assert.equal(checkMessage('<p>Hello <em>world</em></p>').text, 'Hello world');
  assert.equal(checkMessage('<img src="https://evil.example/x.jpg">').ok, false);
});

test('invisible characters and excess whitespace are removed', () => {
  assert.equal(toPlainText('he​llo‮ \u0007world'), 'hello world');
  assert.equal(toPlainText('a\n\n\n\n\nb   c'), 'a\n\nb c');
});

test('links are refused', () => {
  for (const m of [
    'see https://example.com/pic.jpg',
    'http://1.2.3.4/x',
    'go to www.example',
    'visit example.com',
    'pics at foo.xxx',
    'javascript:alert(1)',
    'data:image/png;base64,AAAA',
    'ftp://files',
    'EXAMPLE.COM/path',
  ]) {
    assert.equal(checkMessage(m).ok, false, m);
  }
});

test('explicit terms are refused, including simple obfuscation', () => {
  for (const m of ['free porn here', 'P0RN', 'p.o.r.n', 'so sexy', 'NSFW pics', 'f*ck', 'fuck this']) {
    assert.equal(checkMessage(m).ok, false, m);
  }
});

test('ordinary messages pass unchanged', () => {
  for (const m of [
    'Hello from an agent, with my permission!',
    'Node.js and e.g. U.S. are fine',
    'Essex and Sussex are counties', // "sex" inside a word
    'Cumbria is lovely; I analyzed the data', // "cum", "anal" inside words
    'Ünïcødé ✓ émoji 🎉',
    '1 + 1 = 2, version 2.0',
  ]) {
    const r = checkMessage(m);
    assert.equal(r.ok, true, m);
    assert.equal(r.text, m.normalize('NFKC'));
  }
});

test('length limits', () => {
  assert.equal(checkMessage('x'.repeat(280)).ok, true);
  assert.equal(checkMessage('x'.repeat(281)).ok, false);
  assert.equal(checkMessage('   ').ok, false);
  assert.equal(checkMessage('<br><br>').ok, false);
});

test('display names are cleaned, never rejected', () => {
  assert.equal(cleanName('<b>Ada</b>'), 'Ada');
  assert.equal(cleanName('Ada\nLovelace'), 'Ada Lovelace');
  assert.equal(cleanName('visit example.com'), 'Anonymous');
  assert.equal(cleanName('porn king'), 'Anonymous');
  assert.equal(cleanName('x'.repeat(100)).length, 40);
});
