/**
 * Scanner tool installer.
 *
 * Downloads each binary in TOOL_MANIFEST into ~/.adversa/tools/. Verifies
 * SHA256 against the pinned hash (warns if hash is empty). Uses streaming
 * download + native zip/tar.gz extraction — no external utilities required
 * beyond `tar` and `unzip` which ship on every Mac/Linux.
 */
import { createWriteStream, mkdirSync, existsSync, writeFileSync, readFileSync, chmodSync, statSync, renameSync, rmSync } from 'fs';
import { createHash } from 'crypto';
import { get as httpsGet } from 'https';
import { tmpdir } from 'os';
import { join, dirname } from 'path';
import { spawnSync } from 'child_process';
import {
  TOOL_MANIFEST, ADVERSA_TOOLS_DIR, ADVERSA_MANIFEST_FILE,
  currentPlatform, type ToolSpec, type ToolSource,
} from './manifest';

interface InstalledRecord {
  id:        string;
  version:   string;
  binary:    string;
  installedAt: string;
  sha256?:   string;
  source?:   string;
}

interface InstalledManifest {
  tools: InstalledRecord[];
}

function readInstalled(): InstalledManifest {
  if (!existsSync(ADVERSA_MANIFEST_FILE)) return { tools: [] };
  try {
    return JSON.parse(readFileSync(ADVERSA_MANIFEST_FILE, 'utf-8')) as InstalledManifest;
  } catch {
    return { tools: [] };
  }
}

function writeInstalled(m: InstalledManifest): void {
  mkdirSync(dirname(ADVERSA_MANIFEST_FILE), { recursive: true });
  writeFileSync(ADVERSA_MANIFEST_FILE, JSON.stringify(m, null, 2));
}

/** Public: where ADVERSA-managed binaries live for a given tool id. */
export function managedPath(id: string): string {
  const tool = TOOL_MANIFEST.find((t) => t.id === id);
  if (!tool) return '';
  const ext = currentPlatform() === 'windows-amd64' ? '.exe' : '';
  return join(ADVERSA_TOOLS_DIR, tool.binary + ext);
}

/** Public: is this tool currently installed under ADVERSA's management? */
export function isManaged(id: string): boolean {
  const p = managedPath(id);
  if (!p || !existsSync(p)) return false;
  try { return statSync(p).isFile(); } catch { return false; }
}

/** Public: read the installed-record for a tool (version, install date). */
export function getInstalledRecord(id: string): InstalledRecord | undefined {
  return readInstalled().tools.find((t) => t.id === id);
}

// ── Download with progress callback + redirect following ─────────
function downloadFile(url: string, destPath: string, onProgress?: (pct: number) => void, redirects = 0): Promise<void> {
  return new Promise((resolve, reject) => {
    if (redirects > 5) return reject(new Error('Too many redirects'));
    httpsGet(url, { headers: { 'User-Agent': 'adversa-installer/1.0' } }, (res) => {
      // Follow 30x redirects (GitHub uses redirects for release assets)
      if (res.statusCode && res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
        res.resume();
        downloadFile(res.headers.location, destPath, onProgress, redirects + 1).then(resolve, reject);
        return;
      }
      if (res.statusCode !== 200) {
        res.resume();
        return reject(new Error(`HTTP ${res.statusCode} for ${url}`));
      }
      const total = parseInt(res.headers['content-length'] ?? '0', 10);
      let downloaded = 0;
      const file = createWriteStream(destPath);
      res.on('data', (chunk: Buffer) => {
        downloaded += chunk.length;
        if (total > 0 && onProgress) onProgress(Math.floor((downloaded / total) * 100));
      });
      res.pipe(file);
      file.on('finish', () => { file.close(() => resolve()); });
      file.on('error', (err) => { file.close(); reject(err); });
    }).on('error', reject);
  });
}

// ── Hash verification ────────────────────────────────────────────
async function sha256File(path: string): Promise<string> {
  const hash = createHash('sha256');
  hash.update(readFileSync(path));
  return hash.digest('hex');
}

// ── Extract zip / tar.gz / raw — use system unzip + tar (always present on Mac/Linux) ──
function extract(archivePath: string, archiveType: 'zip' | 'tar.gz' | 'raw', destDir: string, binaryInArchive: string, finalBin: string): void {
  if (archiveType === 'raw') {
    // The archive is the binary itself (rare for these tools)
    renameSync(archivePath, join(destDir, finalBin));
    return;
  }

  const extractDir = join(destDir, '.extract-' + Date.now());
  mkdirSync(extractDir, { recursive: true });

  if (archiveType === 'zip') {
    const r = spawnSync('unzip', ['-q', '-o', archivePath, '-d', extractDir], { stdio: 'inherit' });
    if (r.status !== 0) throw new Error('unzip failed');
  } else if (archiveType === 'tar.gz') {
    const r = spawnSync('tar', ['-xzf', archivePath, '-C', extractDir], { stdio: 'inherit' });
    if (r.status !== 0) throw new Error('tar failed');
  }

  // Find the binary inside the extracted dir (may be in a subdir for some archives)
  const findBin = (dir: string): string | null => {
    const entries = spawnSync('find', [dir, '-name', binaryInArchive, '-type', 'f'], { encoding: 'utf-8' });
    const lines = entries.stdout.split('\n').map((s) => s.trim()).filter(Boolean);
    return lines[0] ?? null;
  };

  const sourcePath = findBin(extractDir);
  if (!sourcePath) throw new Error(`Binary "${binaryInArchive}" not found inside archive`);

  const targetPath = join(destDir, finalBin);
  renameSync(sourcePath, targetPath);
  chmodSync(targetPath, 0o755);

  // Clean up the extracted directory
  try { rmSync(extractDir, { recursive: true, force: true }); } catch { /* ignore */ }
}

// ── Pick the right source for this platform ─────────────────────
function pickSource(tool: ToolSpec): ToolSource {
  const plat = currentPlatform();
  const src = tool.sources.find((s) => s.platform === plat);
  if (!src) throw new Error(`No release for ${tool.id} on ${plat}`);
  return src;
}

// ── Public: install one tool ────────────────────────────────────
export interface InstallProgress {
  onTool?:       (tool: ToolSpec) => void;
  onDownload?:   (pct: number) => void;
  onPhase?:      (phase: 'download' | 'verify' | 'extract' | 'done') => void;
  onWarn?:       (msg: string) => void;
}

export async function installTool(toolId: string, progress: InstallProgress = {}): Promise<void> {
  const tool = TOOL_MANIFEST.find((t) => t.id === toolId);
  if (!tool) throw new Error(`Unknown tool: ${toolId}`);

  progress.onTool?.(tool);

  // Already at the right version?
  const existing = getInstalledRecord(toolId);
  if (existing && existing.version === tool.version && isManaged(toolId)) {
    progress.onPhase?.('done');
    return;
  }

  mkdirSync(ADVERSA_TOOLS_DIR, { recursive: true });

  const src = pickSource(tool);
  const archiveFile = join(tmpdir(), `adversa-${tool.id}-${tool.version}.${src.archiveType === 'tar.gz' ? 'tar.gz' : 'zip'}`);

  // 1. Download
  progress.onPhase?.('download');
  await downloadFile(src.url, archiveFile, progress.onDownload);

  // 2. Verify (or warn if unpinned)
  progress.onPhase?.('verify');
  const actualSha = await sha256File(archiveFile);
  if (src.sha256) {
    if (actualSha.toLowerCase() !== src.sha256.toLowerCase()) {
      try { rmSync(archiveFile); } catch { /* ignore */ }
      throw new Error(`SHA256 mismatch for ${tool.id}: expected ${src.sha256} got ${actualSha}`);
    }
  } else {
    progress.onWarn?.(`${tool.id}: SHA256 not pinned — installed without verification. Pin to lib/tools/manifest.ts:${tool.id}.sources[*].sha256`);
  }

  // 3. Extract + chmod
  progress.onPhase?.('extract');
  const ext = currentPlatform() === 'windows-amd64' ? '.exe' : '';
  extract(archiveFile, src.archiveType, ADVERSA_TOOLS_DIR, src.binaryInArchive, tool.binary + ext);

  // 4. Record
  const installed = readInstalled();
  installed.tools = installed.tools.filter((t) => t.id !== tool.id);
  installed.tools.push({
    id:          tool.id,
    version:     tool.version,
    binary:      tool.binary + ext,
    installedAt: new Date().toISOString(),
    sha256:      actualSha,
    source:      src.url,
  });
  writeInstalled(installed);

  // 5. Cleanup archive
  try { rmSync(archiveFile); } catch { /* ignore */ }

  // 6. Post-install (nuclei templates)
  if (tool.postInstall === 'nuclei-templates') {
    const nucleiBin = managedPath('nuclei');
    if (existsSync(nucleiBin)) {
      // Fire-and-forget; the next scan would download templates anyway
      try {
        spawnSync(nucleiBin, ['-update-templates', '-silent'], { stdio: 'ignore', timeout: 90_000 });
      } catch { /* ignore */ }
    }
  }

  progress.onPhase?.('done');
}

// ── Public: install all tools in manifest ─────────────────────────
export async function installAll(progress: InstallProgress = {}): Promise<{ installed: string[]; skipped: string[]; failed: Array<{ id: string; error: string }> }> {
  const out = { installed: [] as string[], skipped: [] as string[], failed: [] as Array<{ id: string; error: string }> };
  for (const tool of TOOL_MANIFEST) {
    try {
      const before = getInstalledRecord(tool.id)?.version;
      await installTool(tool.id, progress);
      const after = getInstalledRecord(tool.id)?.version;
      if (before === after && before === tool.version) out.skipped.push(tool.id);
      else out.installed.push(tool.id);
    } catch (e) {
      out.failed.push({ id: tool.id, error: e instanceof Error ? e.message : String(e) });
    }
  }
  return out;
}

// ── Public: remove a tool ─────────────────────────────────────────
export function removeTool(toolId: string): boolean {
  const p = managedPath(toolId);
  if (!p || !existsSync(p)) return false;
  try { rmSync(p); } catch { return false; }
  const m = readInstalled();
  m.tools = m.tools.filter((t) => t.id !== toolId);
  writeInstalled(m);
  return true;
}

// ── Public: list managed tool status ──────────────────────────────
export interface ToolStatus {
  id:           string;
  description:  string;
  managedPath?: string;
  installed:    boolean;
  installedVersion?: string;
  pinnedVersion: string;
  upToDate:     boolean;
}

export function listStatus(): ToolStatus[] {
  const installed = readInstalled();
  return TOOL_MANIFEST.map((tool) => {
    const rec = installed.tools.find((t) => t.id === tool.id);
    const present = isManaged(tool.id);
    return {
      id:              tool.id,
      description:     tool.description,
      managedPath:     present ? managedPath(tool.id) : undefined,
      installed:       present,
      installedVersion: rec?.version,
      pinnedVersion:   tool.version,
      upToDate:        present && rec?.version === tool.version,
    };
  });
}
