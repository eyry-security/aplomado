// Aplomado browser bridge: one long-lived headless Chrome per scan, driven by
// the Chrome DevTools Protocol and the standard chrome-devtools-mcp server.
// Invoked one-shot per agent tool call; Chrome itself persists across calls.

import { spawn } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import readline from 'node:readline';

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

function resolveChrome() {
  const candidates = [
    process.env.APLOMADO_CHROME_BIN,
    process.env.CHROME_BIN,
    '/usr/local/bin/google-chrome',
    '/usr/bin/google-chrome',
    '/usr/bin/chromium',
    '/usr/bin/chromium-browser',
    '/opt/chrome/chrome',
  ].filter(Boolean);
  for (const candidate of candidates) {
    try {
      fs.accessSync(candidate, fs.constants.X_OK);
      return candidate;
    } catch {}
  }
  return '';
}

const CHROME_BIN = resolveChrome();
const MCP_BIN = process.env.CHROME_DEVTOOLS_MCP_BIN || 'chrome-devtools-mcp';

function pidAlive(pid) {
  if (!Number.isInteger(pid) || pid <= 0) return false;
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
}

async function readState(stateDir) {
  const stateFile = path.join(stateDir, 'chrome.json');
  try {
    return JSON.parse(fs.readFileSync(stateFile, 'utf8'));
  } catch {
    return null;
  }
}

function writeState(stateDir, state) {
  fs.writeFileSync(path.join(stateDir, 'chrome.json'), JSON.stringify(state));
}

async function waitForDevTools(profileDir, deadline) {
  const activePort = path.join(profileDir, 'DevToolsActivePort');
  let lastError = '';
  while (Date.now() < deadline) {
    try {
      const lines = fs.readFileSync(activePort, 'utf8').trim().split('\n');
      const port = Number(lines[0]);
      const wsPath = (lines[1] || '').trim();
      if (port > 0 && wsPath) {
        const response = await fetch(`http://127.0.0.1:${port}/json/version`);
        if (response.ok) return { port, wsPath };
        lastError = `devtools HTTP ${response.status}`;
      }
    } catch (error) {
      lastError = String(error && error.message ? error.message : error);
    }
    await sleep(100);
  }
  throw new Error(`Chrome did not expose DevTools in time (${lastError})`);
}

async function ensureChrome(stateDir, timeoutMs) {
  if (!CHROME_BIN) {
    throw new Error(
      'headless Chrome is not installed in the sandbox image (expected ' +
        'google-chrome or chromium); rebuild the Aplomado sandbox image',
    );
  }
  fs.mkdirSync(stateDir, { recursive: true });
  const existing = await readState(stateDir);
  if (existing && pidAlive(existing.pid)) {
    try {
      const response = await fetch(
        `http://127.0.0.1:${existing.port}/json/version`,
      );
      if (response.ok) return existing;
    } catch {}
  }
  const profileDir = path.join(stateDir, 'profile');
  for (const lock of ['SingletonLock', 'SingletonSocket', 'SingletonCookie']) {
    try {
      fs.rmSync(path.join(profileDir, lock), { force: true });
    } catch {}
  }
  fs.mkdirSync(profileDir, { recursive: true });
  const args = [
    '--headless=new',
    '--no-sandbox',
    '--disable-gpu',
    '--disable-dev-shm-usage',
    '--disable-background-networking',
    '--disable-default-apps',
    '--disable-extensions',
    '--disable-sync',
    '--metrics-recording-only',
    '--mute-audio',
    '--no-first-run',
    '--safebrowsing-disable-auto-update',
    `--user-data-dir=${profileDir}`,
    '--remote-debugging-port=0',
    'about:blank',
  ];
  const child = spawn(CHROME_BIN, args, {
    detached: true,
    stdio: 'ignore',
    env: process.env,
  });
  child.unref();
  const deadline = Date.now() + Math.min(timeoutMs, 30_000);
  const { port, wsPath } = await waitForDevTools(profileDir, deadline);
  const state = { pid: child.pid, port, wsPath };
  writeState(stateDir, state);
  return state;
}

class CDP {
  constructor(url, timeoutMs) {
    this.url = url;
    this.timeoutMs = timeoutMs;
    this.nextId = 1;
    this.pending = new Map();
    this.ws = null;
  }

  static async connect(url, timeoutMs) {
    const cdp = new CDP(url, timeoutMs);
    await cdp.open();
    return cdp;
  }

  async open() {
    await new Promise((resolve, reject) => {
      this.ws = new WebSocket(this.url);
      const timer = setTimeout(
        () => reject(new Error('CDP WebSocket connect timed out')),
        this.timeoutMs,
      );
      this.ws.onopen = () => {
        clearTimeout(timer);
        resolve();
      };
      this.ws.onerror = (event) => {
        clearTimeout(timer);
        reject(new Error(`CDP WebSocket failed: ${event.message || 'error'}`));
      };
    });
    this.ws.onmessage = (event) => {
      let message;
      try {
        message = JSON.parse(event.data);
      } catch {
        return;
      }
      if (message.id && this.pending.has(message.id)) {
        const pending = this.pending.get(message.id);
        this.pending.delete(message.id);
        clearTimeout(pending.timer);
        if (message.error) pending.reject(new Error(message.error.message || 'CDP error'));
        else pending.resolve(message.result || {});
      }
    };
  }

  send(method, params = {}, sessionId = null) {
    const id = this.nextId++;
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(id);
        reject(new Error(`browser action ${method} timed out`));
      }, this.timeoutMs);
      this.pending.set(id, { resolve, reject, timer });
      const payload = { id, method, params };
      if (sessionId) payload.sessionId = sessionId;
      this.ws.send(JSON.stringify(payload));
    });
  }

  close() {
    try {
      this.ws.close();
    } catch {}
  }
}

async function openPage(cdp) {
  const { targetId } = await cdp.send('Target.createTarget', { url: 'about:blank' });
  const { sessionId } = await cdp.send('Target.attachToTarget', {
    targetId,
    flatten: true,
  });
  await cdp.send('Page.enable', {}, sessionId);
  await cdp.send('Runtime.enable', {}, sessionId);
  await cdp.send('Network.enable', {}, sessionId);
  return { targetId, sessionId };
}

async function closePage(cdp, page) {
  try {
    await cdp.send('Target.closeTarget', { targetId: page.targetId });
  } catch {}
}

async function setCookies(cdp, sessionId, cookies, url) {
  for (const cookie of cookies || []) {
    if (!cookie || !cookie.name) continue;
    const params = {
      name: String(cookie.name),
      value: String(cookie.value ?? ''),
      path: cookie.path || '/',
    };
    if (cookie.url) params.url = cookie.url;
    else if (url) params.url = url;
    if (!params.url && cookie.domain) params.domain = cookie.domain;
    if (cookie.secure) params.secure = true;
    if (cookie.http_only || cookie.httpOnly) params.httpOnly = true;
    const expires = Number(cookie.expires || 0);
    if (expires > 0) params.expires = expires;
    try {
      await cdp.send('Network.setCookie', params, sessionId);
    } catch (error) {
      // A single unusable cookie must not block authentication for the rest.
      process.stderr.write(`cookie set failed: ${error.message}\n`);
    }
  }
}

async function allCookies(cdp, page) {
  const sessionId = page && page.sessionId ? page.sessionId : undefined;
  try {
    const result = await cdp.send('Network.getAllCookies', {}, sessionId);
    if (Array.isArray(result.cookies) && result.cookies.length) {
      return result.cookies;
    }
  } catch {}
  try {
    const result = await cdp.send('Storage.getCookies', {}, sessionId);
    if (Array.isArray(result.cookies) && result.cookies.length) {
      return result.cookies;
    }
  } catch {}
  try {
    const result = await cdp.send('Network.getCookies', {}, sessionId);
    if (Array.isArray(result.cookies)) return result.cookies;
  } catch {}
  return [];
}

async function waitForReady(cdp, sessionId, timeoutMs) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      const result = await cdp.send(
        'Runtime.evaluate',
        { expression: 'document.readyState', returnByValue: true },
        sessionId,
      );
      if (['interactive', 'complete'].includes(result.result?.value)) {
        await sleep(400);
        return;
      }
    } catch {}
    await sleep(100);
  }
  throw new Error('page did not finish loading before the browser timeout');
}

async function probePage(cdp, sessionId) {
  const result = await cdp.send(
    'Runtime.evaluate',
    {
      expression:
        'JSON.stringify({title: document.title || "", url: location.href || ""})',
      returnByValue: true,
    },
    sessionId,
  );
  try {
    return JSON.parse(result.result?.value || '{}');
  } catch {
    return {};
  }
}

function browserUrl(state) {
  return `ws://127.0.0.1:${state.port}${state.wsPath}`;
}

async function withBrowser(payload, fn) {
  const timeoutMs = Number(payload.timeout_ms || 120_000);
  const stateDir = path.resolve(payload.state_dir || 'scratch/.browser');
  const state = await ensureChrome(stateDir, timeoutMs);
  const cdp = await CDP.connect(browserUrl(state), timeoutMs);
  try {
    return await fn(cdp, state, timeoutMs);
  } finally {
    cdp.close();
  }
}

async function screenshot(payload) {
  return withBrowser(payload, async (cdp) => {
    const page = await openPage(cdp);
    try {
      if (payload.cookies && payload.cookies.length) {
        await setCookies(cdp, page.sessionId, payload.cookies, payload.url);
      }
      const navigation = await cdp.send(
        'Page.navigate',
        { url: payload.url },
        page.sessionId,
      );
      if (navigation.errorText) {
        throw new Error(`navigation failed: ${navigation.errorText}`);
      }
      const timeoutMs = Number(payload.timeout_ms || 120_000);
      await waitForReady(cdp, page.sessionId, timeoutMs);
      const probe = await probePage(cdp, page.sessionId);
      const shot = await cdp.send(
        'Page.captureScreenshot',
        {
          format: 'png',
          fromSurface: true,
          captureBeyondViewport: Boolean(payload.full_page),
        },
        page.sessionId,
      );
      const outputPath = path.resolve(
        payload.output_path || 'scratch/shots/screenshot.png',
      );
      fs.mkdirSync(path.dirname(outputPath), { recursive: true });
      fs.writeFileSync(outputPath, Buffer.from(shot.data || '', 'base64'));
      const cookies = await allCookies(cdp, page);
      return {
        ok: true,
        path: payload.output_path,
        title: probe.title || '',
        final_url: probe.url || payload.url,
        cookies,
      };
    } finally {
      await closePage(cdp, page);
    }
  });
}

async function auth(payload) {
  return withBrowser(payload, async (cdp) => {
    const page = await openPage(cdp);
    try {
      await setCookies(cdp, page.sessionId, payload.cookies || [], payload.url);
      return { ok: true, cookies: await allCookies(cdp, page) };
    } finally {
      await closePage(cdp, page);
    }
  });
}

function mcpRpc(child, timeoutMs) {
  const responses = new Map();
  const lines = readline.createInterface({ input: child.stdout });
  lines.on('line', (line) => {
    if (!line.trim()) return;
    let message;
    try {
      message = JSON.parse(line);
    } catch {
      return;
    }
    if (message.id && responses.has(message.id)) {
      const pending = responses.get(message.id);
      responses.delete(message.id);
      clearTimeout(pending.timer);
      if (message.error) pending.reject(new Error(message.error.message || 'MCP error'));
      else pending.resolve(message.result || {});
    }
  });
  let nextId = 1;
  return (method, params) =>
    new Promise((resolve, reject) => {
      const id = nextId++;
      const timer = setTimeout(() => {
        responses.delete(id);
        reject(new Error(`browser MCP call ${method} timed out`));
      }, timeoutMs);
      responses.set(id, { resolve, reject, timer });
      child.stdin.write(
        JSON.stringify({ jsonrpc: '2.0', id, method, params }) + '\n',
      );
    });
}

async function mcp(payload) {
  return withBrowser(payload, async (cdp, state) => {
    if (payload.cookies && payload.cookies.length) {
      const page = await openPage(cdp);
      try {
        await setCookies(cdp, page.sessionId, payload.cookies, payload.url);
      } finally {
        await closePage(cdp, page);
      }
    }
    const timeoutMs = Number(payload.timeout_ms || 120_000);
    const child = spawn(
      MCP_BIN,
      [
        '--headless',
        '--browserUrl',
        `http://127.0.0.1:${state.port}`,
        '--no-page-id-routing',
        '--no-usage-statistics',
        '--no-performance-crux',
      ],
      {
        stdio: ['pipe', 'pipe', 'pipe'],
        env: {
          ...process.env,
          CHROME_DEVTOOLS_MCP_NO_USAGE_STATISTICS: '1',
          CHROME_DEVTOOLS_MCP_NO_UPDATE_CHECKS: '1',
          CI: '1',
        },
      },
    );
    let stderr = '';
    child.stderr.on('data', (chunk) => {
      if (stderr.length < 4000) stderr += chunk.toString();
    });
    const rpc = mcpRpc(child, timeoutMs);
    try {
      await rpc('initialize', {
        protocolVersion: '2024-11-05',
        capabilities: {},
        clientInfo: { name: 'aplomado', version: '0.1.0' },
      });
      child.stdin.write(
        JSON.stringify({ jsonrpc: '2.0', method: 'notifications/initialized' }) +
          '\n',
      );
      const result = await rpc('tools/call', {
        name: payload.tool,
        arguments: payload.arguments || {},
      });
      let cookies = [];
      try {
        const inspection = await openPage(cdp);
        cookies = await allCookies(cdp, inspection);
        await closePage(cdp, inspection);
      } catch {}
      if (result.isError) {
        return {
          ok: false,
          error: JSON.stringify(result.content || result),
          cookies,
        };
      }
      return { ok: true, result, cookies };
    } catch (error) {
      const detail = stderr.trim() ? `: ${stderr.trim().split('\n')[0]}` : '';
      throw new Error(`${error.message}${detail}`);
    } finally {
      try {
        child.kill();
      } catch {}
    }
  });
}

async function main() {
  const raw = process.argv[2] || fs.readFileSync(0, 'utf8') || '{}';
  const payload = JSON.parse(raw);
  const action = payload.action;
  let result;
  if (action === 'screenshot') result = await screenshot(payload);
  else if (action === 'auth') result = await auth(payload);
  else if (action === 'mcp') result = await mcp(payload);
  else throw new Error(`unknown browser action ${action}`);
  process.stdout.write(JSON.stringify(result) + '\n');
}

main().catch((error) => {
  process.stdout.write(
    JSON.stringify({ ok: false, error: String(error.message || error) }) + '\n',
  );
  process.exitCode = 1;
});
