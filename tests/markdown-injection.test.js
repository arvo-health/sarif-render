/**
 * Spec for SARIF-to-comment Markdown injection.
 *
 * These tests exercise the action entry point (src/index.ts): schema validation,
 * convert/formatSummaryComment, and GitHubPRCommenter posting through axios 1.9.0.
 * They fail while scanner message text, rule ids, tool names, artifact URIs, and
 * GITHUB_HEAD_REF are copied into the Markdown comment or the HTML marker.
 *
 * A comment is safe when:
 * - SARIF text cannot start a new line, so a payload heading is not its own line.
 * - The contiguous tokens "@victim-user" and "https://evil.example" do not occur
 *   (mentions and autolinked URLs are broken, while the readable words remain).
 * - Raw HTML tags from the payload ("<a " and the payload "<img") do not occur.
 * - "-->" does not occur in the Markdown body. A pull-request marker may contain
 *   exactly one "-->", closing the first line and nothing earlier.
 * - Each finding row has five unescaped "|" cells.
 * - The scanner line is one code span or one <code> element with no nested
 *   backtick or "<".
 * - A location link is emitted only for an allowlisted branch and relative path,
 *   and the href is exactly "../blob/<branch>/<path>#L<line>" for that same path
 *   and line. Allowlisted means segments of [A-Za-z0-9._-]+ separated by single
 *   slashes, with no empty, ".", or ".." segment.
 *
 * Run:
 *   node --test tests/markdown-injection.test.js
 *
 * Not rendered today, so not asserted as sinks: result.message.markdown,
 * rule.help.text, rule.help.markdown, and rule.fullDescription (copied onto the
 * finding and then dropped). titleName comes from the action input, not SARIF.
 */

const assert = require('node:assert/strict');
const fs = require('node:fs');
const http = require('node:http');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');
const { spawn } = require('node:child_process');

require('ts-node/register');

const { validateSarif } = require('../src/validateSarif');
const { convert } = require('../src/convert');

const MENTION = '@victim-user';
const EVIL_ORIGIN = 'https://evil.example';
const HEADING = '## Forged heading';
const SAFE_BRANCH = 'feature/fix-1';

const DRIVER = [
  'Tool` -->',
  HEADING,
  `${MENTION} ${EVIL_ORIGIN}/driver`,
].join('\n');

const MESSAGE = [
  'safe text --> still safe',
  '',
  HEADING,
  `${MENTION} see [phish](${EVIL_ORIGIN}/phish) and <a href="${EVIL_ORIGIN}/phish">login</a> <img src="${EVIL_ORIGIN}/x.svg">`,
].join('\n');

const RULE_ID = `RULE|EXTRA|CELL\n${MENTION}`;

function result(level, uri, line, message, ruleId) {
  return {
    level,
    ruleId,
    message: { text: message, markdown: 'RAW-MARKDOWN-NOT-A-SINK ' + MESSAGE },
    locations: [
      {
        physicalLocation: {
          artifactLocation: { uri },
          region: { startLine: line },
        },
      },
    ],
  };
}

function maliciousSarif() {
  return {
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: DRIVER,
            rules: [
              {
                id: 'unused-by-formatter',
                fullDescription: { text: 'DESCRIPTION-NOT-A-SINK ' + MESSAGE },
                help: {
                  text: 'HELP-TEXT-NOT-A-SINK ' + MESSAGE,
                  markdown: 'HELP-MARKDOWN-NOT-A-SINK ' + MESSAGE,
                },
              },
            ],
          },
        },
        results: [
          result('error', 'src/ok.js', 3, MESSAGE, RULE_ID),
          result('warning', 'a)(' + EVIL_ORIGIN + '/phish)', 4, 'warning-marker', 'warn-rule'),
          result('note', '../secret.js', 6, 'traversal-marker', 'note-rule'),
          result('error', 'javascript:evil', 7, 'scheme-marker', 'scheme-rule'),
          result('warning', EVIL_ORIGIN + '/abs', 8, 'absolute-marker', 'abs-rule'),
          result('note', '/etc/passwd', 9, 'absolute-path-marker', 'root-rule'),
          result('error', 'src/app.js?x=' + EVIL_ORIGIN + '/q', 11, 'query-marker', 'query-rule'),
        ],
      },
      {
        tool: { driver: { name: 'SecondTool' } },
        results: [
          result('error', 'src/other.js', 10, 'second-run-marker ' + MENTION, 'second-rule'),
        ],
      },
    ],
  };
}

function benignSarif() {
  return {
    version: '2.1.0',
    runs: [
      {
        tool: { driver: { name: 'ESLint' } },
        results: [
          result('warning', 'src/ok.js', 3, 'assigned but never used', 'no-unused-vars'),
        ],
      },
    ],
  };
}

function assertAbsent(haystack, needle) {
  const at = haystack.indexOf(needle);
  assert.equal(
    at,
    -1,
    at === -1 ? needle : haystack.slice(Math.max(0, at - 100), at + needle.length + 100)
  );
}

function locationHrefs(markdown) {
  return [...markdown.matchAll(/\]\(([^)\n ]*)\)/g)].map((match) => match[1]);
}

function assertFindingRows(markdown) {
  const rows = markdown.split('\n').filter((line) => line.includes('width="24"'));
  assert.ok(rows.length >= 1, 'expected one rendered row per location');
  for (const row of rows) {
    let pipes = 0;
    for (let i = 0; i < row.length; i += 1) {
      if (row[i] === '|' && row[i - 1] !== '\\') pipes += 1;
    }
    assert.equal(pipes, 5, row);
  }
}

function assertScannerLine(markdown) {
  const lines = markdown.split('\n').filter((line) => line.startsWith('- Scanner:'));
  assert.equal(lines.length, 1);
  const line = lines[0];
  const codeSpan = /^- Scanner: `[^`]*`$/.test(line);
  const htmlCode = /^- Scanner: <code>[^<]*<\/code>$/.test(line);
  assert.ok(codeSpan || htmlCode, line);
}

function assertNoActivePayload(markdown) {
  assertAbsent(markdown, MENTION);
  assertAbsent(markdown, EVIL_ORIGIN);
  assertAbsent(markdown, 'http://evil.example');
  assertAbsent(markdown, '<a ');
  assertAbsent(markdown, '<img src="' + EVIL_ORIGIN);
  assert.equal(markdown.split('-->').length - 1, 0, markdown);
  assert.equal(
    markdown.split('\n').some((line) => line.trim() === HEADING),
    false
  );
}

function assertSafeLocations(markdown, branch, expectedHrefs) {
  const hrefs = locationHrefs(markdown).sort();
  assert.deepEqual(hrefs, expectedHrefs.slice().sort());
  const prefix = `../blob/${branch}/`;
  for (const href of hrefs) {
    assert.ok(href.startsWith(prefix), href);
  }
}

function render(sarif, headRef) {
  const previous = process.env.GITHUB_HEAD_REF;
  const previousExit = process.exit;
  if (headRef === undefined) delete process.env.GITHUB_HEAD_REF;
  else process.env.GITHUB_HEAD_REF = headRef;
  process.exit = (code) => {
    throw new Error('process.exit ' + code);
  };
  try {
    validateSarif(sarif);
    return convert(sarif);
  } finally {
    process.exit = previousExit;
    if (previous === undefined) delete process.env.GITHUB_HEAD_REF;
    else process.env.GITHUB_HEAD_REF = previous;
  }
}

function writeSarif(sarif) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'sarif-render-'));
  const file = path.join(directory, 'results.sarif');
  fs.writeFileSync(file, JSON.stringify(sarif));
  return { directory, file };
}

function startServer(handler) {
  const requests = [];
  const server = http.createServer(async (req, res) => {
    const chunks = [];
    for await (const chunk of req) chunks.push(chunk);
    const raw = Buffer.concat(chunks).toString('utf8');
    const recorded = { method: req.method, url: req.url, raw };
    requests.push(recorded);
    handler(recorded, res);
  });
  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => {
      const address = server.address();
      resolve({
        requests,
        url: `http://127.0.0.1:${address.port}`,
        close: () => new Promise((done) => server.close(() => done())),
      });
    });
  });
}

function respondJson(res, status, payload) {
  const body = JSON.stringify(payload);
  res.writeHead(status, { 'content-type': 'application/json', 'content-length': Buffer.byteLength(body) });
  res.end(body);
}

function runAction(sarifFile, headRef, serverUrl, postTarget) {
  const env = { ...process.env };
  delete env.INPUT_TITLE_NAME;
  delete env.GITHUB_PR_NUMBER;
  env.INPUT_SARIF_FILE = sarifFile;
  env.GITHUB_TOKEN = 'placeholder-not-a-secret';
  env.GITHUB_REPOSITORY = 'octo/example';
  env.GITHUB_HOST = serverUrl;
  env.GITHUB_HEAD_REF = headRef;
  if (postTarget) {
    env.INPUT_POST_TARGET = postTarget;
    env.GITHUB_EVENT_NAME = 'workflow_dispatch';
  } else {
    delete env.INPUT_POST_TARGET;
    env.GITHUB_EVENT_NAME = 'pull_request';
    env.GITHUB_PR_NUMBER = '7';
    env.GITHUB_REF = 'refs/pull/7/merge';
  }
  return new Promise((resolve) => {
    const child = spawn(process.execPath, ['--require', 'ts-node/register', 'src/index.ts'], {
      cwd: path.resolve(__dirname, '..'),
      env,
    });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (chunk) => {
      stdout += chunk;
    });
    child.stderr.on('data', (chunk) => {
      stderr += chunk;
    });
    child.on('close', (code) => resolve({ code, stdout, stderr }));
  });
}

function postedBodies(requests) {
  return requests
    .filter((request) => request.method === 'POST' || request.method === 'PATCH')
    .map((request) => JSON.parse(request.raw).body);
}

test('schema validation accepts the payload and the summary escapes it', () => {
  const markdown = render(maliciousSarif(), SAFE_BRANCH);
  assertNoActivePayload(markdown);
  assertFindingRows(markdown);
  assertScannerLine(markdown);
  assertSafeLocations(markdown, SAFE_BRANCH, [
    '../blob/feature/fix-1/src/ok.js#L3',
    '../blob/feature/fix-1/src/other.js#L10',
  ]);
  for (const readable of [
    'safe text',
    'still safe',
    'Forged heading',
    'victim-user',
    'phish',
    'EXTRA',
    'warning-marker',
    'traversal-marker',
    'scheme-marker',
    'absolute-marker',
    'absolute-path-marker',
    'query-marker',
    'second-run-marker',
    'ok.js',
    'other.js',
  ]) {
    assert.ok(markdown.includes(readable), readable);
  }
});

test('a git-valid branch containing ) is not used as a location link', () => {
  const markdown = render(benignSarif(), 'a)b');
  assert.deepEqual(locationHrefs(markdown), []);
  assert.ok(markdown.includes('assigned but never used'));
  assert.ok(markdown.includes('ok.js'));
  assertScannerLine(markdown);
});

test('a git-valid branch containing @ is not copied into the comment', () => {
  const markdown = render(benignSarif(), 'release@victim-user');
  assertAbsent(markdown, MENTION);
  assert.deepEqual(locationHrefs(markdown), []);
  assert.ok(markdown.includes('assigned but never used'));
  assertScannerLine(markdown);
});

test('an allowlisted branch and relative path keep the same line in the link', () => {
  const markdown = render(benignSarif(), SAFE_BRANCH);
  assertSafeLocations(markdown, SAFE_BRANCH, ['../blob/feature/fix-1/src/ok.js#L3']);
  assert.ok(markdown.includes('assigned but never used'));
  assertScannerLine(markdown);
  assert.match(markdown, /^- Scanner: `ESLint`$/m);
});

test('missing GITHUB_HEAD_REF links the allowlisted path on main', () => {
  const markdown = render(benignSarif(), undefined);
  assertSafeLocations(markdown, 'main', ['../blob/main/src/ok.js#L3']);
});

async function postedActionBody(sarif, headRef, postTarget, handler) {
  const server = await startServer(handler);
  const fixture = writeSarif(sarif);
  try {
    const result = await runAction(fixture.file, headRef, server.url, postTarget);
    assert.equal(
      result.code,
      0,
      result.stderr + '\n' + result.stdout + '\n' + JSON.stringify(server.requests.map((r) => r.method + ' ' + r.url))
    );
    const bodies = postedBodies(server.requests);
    assert.equal(bodies.length, 1, JSON.stringify(server.requests.map((r) => r.method + ' ' + r.url)));
    return bodies[0];
  } finally {
    fs.rmSync(fixture.directory, { recursive: true, force: true });
    await server.close();
  }
}

function assertPosted(body) {
  const newline = body.indexOf('\n');
  const firstLine = newline === -1 ? body : body.slice(0, newline);
  let markdown = body;
  if (firstLine.startsWith('<!-- SARIFCourier:')) {
    assert.equal(firstLine.indexOf('-->'), firstLine.length - 3, firstLine);
    markdown = newline === -1 ? '' : body.slice(newline + 1);
  }
  assertNoActivePayload(markdown);
  assertFindingRows(markdown);
  assertScannerLine(markdown);
  assertSafeLocations(markdown, SAFE_BRANCH, [
    '../blob/feature/fix-1/src/ok.js#L3',
    '../blob/feature/fix-1/src/other.js#L10',
  ]);
  assert.ok(markdown.includes('safe text'));
  assert.ok(markdown.includes('second-run-marker'));
  assertAbsent(body, MENTION);
  assertAbsent(body, EVIL_ORIGIN);
}

test('pull request create posts the escaped summary as the comment body', async () => {
  const body = await postedActionBody(maliciousSarif(), SAFE_BRANCH, '', (request, res) => {
    if (request.method === 'GET' && request.url === '/repos/octo/example/issues/7/comments') {
      respondJson(res, 200, []);
      return;
    }
    if (request.method === 'POST' && request.url === '/repos/octo/example/issues/7/comments') {
      respondJson(res, 201, { id: 1 });
      return;
    }
    respondJson(res, 404, {});
  });
  assert.ok(body.startsWith('<!-- SARIFCourier:'));
  assertPosted(body);
});

test('pull request update posts the escaped summary through the marker path', async () => {
  const marker = `<!-- SARIFCourier:${DRIVER} -->`;
  const body = await postedActionBody(maliciousSarif(), SAFE_BRANCH, '', (request, res) => {
    if (request.method === 'GET' && request.url === '/repos/octo/example/issues/7/comments') {
      respondJson(res, 200, [{ id: 4242, body: marker + '\nold' }]);
      return;
    }
    if (request.method === 'PATCH' && request.url === '/repos/octo/example/issues/comments/4242') {
      respondJson(res, 200, { id: 4242 });
      return;
    }
    respondJson(res, 404, {});
  });
  assert.ok(body.startsWith('<!-- SARIFCourier:'));
  assertPosted(body);
});

test('non-array comment list still posts an escaped body', async () => {
  const body = await postedActionBody(maliciousSarif(), SAFE_BRANCH, '', (request, res) => {
    if (request.method === 'GET' && request.url === '/repos/octo/example/issues/7/comments') {
      respondJson(res, 200, {});
      return;
    }
    if (request.method === 'POST' && request.url === '/repos/octo/example/issues/7/comments') {
      respondJson(res, 201, { id: 1 });
      return;
    }
    respondJson(res, 404, {});
  });
  assertPosted(body);
});

test('a new issue is created with the escaped summary and no earlier write', async () => {
  const server = await startServer((request, res) => {
    if (request.method === 'GET' && request.url.startsWith('/repos/octo/example/issues?')) {
      respondJson(res, 200, []);
      return;
    }
    if (request.method === 'POST' && request.url === '/repos/octo/example/issues') {
      respondJson(res, 201, { number: 15 });
      return;
    }
    respondJson(res, 404, {});
  });
  const fixture = writeSarif(maliciousSarif());
  try {
    const result = await runAction(fixture.file, SAFE_BRANCH, server.url, 'issue');
    assert.equal(result.code, 0, result.stderr);
    assert.deepEqual(
      server.requests.map((request) => request.method + ' ' + request.url.split('?')[0]),
      ['GET /repos/octo/example/issues', 'POST /repos/octo/example/issues']
    );
    const created = JSON.parse(server.requests[1].raw);
    assert.equal(created.title, 'SAST Security Results 🚨');
    assertPosted(created.body);
  } finally {
    fs.rmSync(fixture.directory, { recursive: true, force: true });
    await server.close();
  }
});

test('an existing issue comment receives the escaped summary', async () => {
  const body = await postedActionBody(maliciousSarif(), SAFE_BRANCH, 'issue', (request, res) => {
    if (request.method === 'GET' && request.url.startsWith('/repos/octo/example/issues?')) {
      respondJson(res, 200, [{ number: 15, title: 'SAST Security Results 🚨' }]);
      return;
    }
    if (request.method === 'POST' && request.url === '/repos/octo/example/issues/15/comments') {
      respondJson(res, 201, { id: 3 });
      return;
    }
    respondJson(res, 404, {});
  });
  assertPosted(body);
});

test('a SARIF file that fails schema validation posts nothing', async () => {
  const server = await startServer((request, res) => {
    respondJson(res, 500, {});
  });
  const fixture = writeSarif({
    version: '2.1.0',
    runs: [
      {
        tool: { driver: { name: 'ESLint' } },
        results: [
          result('not-a-level', 'src/ok.js', 1, 'should-not-post', 'rule'),
        ],
      },
    ],
  });
  try {
    const result = await runAction(fixture.file, SAFE_BRANCH, server.url, '');
    assert.notEqual(result.code, 0);
    assert.deepEqual(server.requests, []);
    assert.equal(fs.readdirSync(fixture.directory).includes('sarif-2-md-output.md'), false);
  } finally {
    fs.rmSync(fixture.directory, { recursive: true, force: true });
    await server.close();
  }
});

test('benign action output posts one allowlisted location link', async () => {
  const body = await postedActionBody(benignSarif(), SAFE_BRANCH, '', (request, res) => {
    if (request.method === 'GET' && request.url === '/repos/octo/example/issues/7/comments') {
      respondJson(res, 200, []);
      return;
    }
    if (request.method === 'POST' && request.url === '/repos/octo/example/issues/7/comments') {
      respondJson(res, 201, { id: 1 });
      return;
    }
    respondJson(res, 404, {});
  });
  const markdown = body.replace(/^<!-- SARIFCourier:ESLint -->\n/, '');
  assertSafeLocations(markdown, SAFE_BRANCH, ['../blob/feature/fix-1/src/ok.js#L3']);
  assert.ok(markdown.includes('assigned but never used'));
  assertScannerLine(markdown);
});
