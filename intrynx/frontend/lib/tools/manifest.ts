/**
 * Bundled scanner tools manifest.
 *
 * ADVERSA downloads these into ~/.adversa/tools/ on install. Clients never
 * need to run go install or homebrew.
 *
 * Pinning policy:
 *   - version: exact release tag (no "latest" — reproducible builds)
 *   - sha256:  pinned hash from official release checksums file (verify on download)
 *   - sources: official release URLs only (no random mirrors)
 *
 * To bump a tool:
 *   1. Pick a new release on the upstream GitHub
 *   2. Update version + every platform URL
 *   3. Update sha256 from the release's checksums.txt
 *   4. Run `adversa tools update` to verify on every supported platform
 */
import { homedir, arch as osArch, platform as osPlatform } from 'os';
import { join } from 'path';

export const ADVERSA_TOOLS_DIR = join(homedir(), '.adversa', 'tools');
export const ADVERSA_MANIFEST_FILE = join(ADVERSA_TOOLS_DIR, '.installed.json');

export type Platform =
  | 'darwin-arm64' | 'darwin-amd64'
  | 'linux-amd64'  | 'linux-arm64'
  | 'windows-amd64';

export interface ToolSource {
  platform:    Platform;
  url:         string;
  /** Pinned SHA256 of the archive. Empty string = verification skipped (warn). */
  sha256:      string;
  /** Format of the archive */
  archiveType: 'zip' | 'tar.gz' | 'raw';
  /** Path of the binary inside the archive (may differ from tool name) */
  binaryInArchive: string;
}

export interface ToolSpec {
  id:          string;                 // canonical id used by runners ('naabu', 'httpx', etc.)
  description: string;
  version:     string;
  /** Final binary name when installed (without extension on Unix, .exe on Windows) */
  binary:      string;
  /** Skip if this tool isn't actually needed on the current platform */
  optional?:   boolean;
  sources:     ToolSource[];
  /** Some tools need a post-install step (nuclei needs templates) */
  postInstall?: 'nuclei-templates' | 'none';
}

/** Detect current platform string used in the manifest. */
export function currentPlatform(): Platform {
  const a = osArch();
  const p = osPlatform();
  if (p === 'darwin')  return a === 'arm64' ? 'darwin-arm64' : 'darwin-amd64';
  if (p === 'linux')   return a === 'arm64' ? 'linux-arm64'  : 'linux-amd64';
  if (p === 'win32')   return 'windows-amd64';
  throw new Error(`Unsupported platform: ${p}/${a}`);
}

// ── The actual manifest ──────────────────────────────────────────
//
// SHA256 values below are intentionally empty strings: pin them with the
// real release checksum the FIRST time you install on each platform. The
// installer warns when sha256 is empty but proceeds; in production deploy
// you must pin every hash.
//
// Hash lookup procedure (per tool, per release):
//   curl -s https://github.com/<repo>/releases/download/<version>/<repo>_<v>_checksums.txt
//   grep <archive-name>

export const TOOL_MANIFEST: ToolSpec[] = [
  {
    id:          'naabu',
    description: 'Fast TCP port discovery (ProjectDiscovery)',
    version:     'v2.3.5',
    binary:      'naabu',
    sources: [
      { platform: 'darwin-arm64', sha256: '', archiveType: 'zip',
        url:      'https://github.com/projectdiscovery/naabu/releases/download/v2.3.5/naabu_2.3.5_macOS_arm64.zip',
        binaryInArchive: 'naabu' },
      { platform: 'darwin-amd64', sha256: '', archiveType: 'zip',
        url:      'https://github.com/projectdiscovery/naabu/releases/download/v2.3.5/naabu_2.3.5_macOS_amd64.zip',
        binaryInArchive: 'naabu' },
      { platform: 'linux-amd64',  sha256: '', archiveType: 'zip',
        url:      'https://github.com/projectdiscovery/naabu/releases/download/v2.3.5/naabu_2.3.5_linux_amd64.zip',
        binaryInArchive: 'naabu' },
      { platform: 'linux-arm64',  sha256: '', archiveType: 'zip',
        url:      'https://github.com/projectdiscovery/naabu/releases/download/v2.3.5/naabu_2.3.5_linux_arm64.zip',
        binaryInArchive: 'naabu' },
      { platform: 'windows-amd64', sha256: '', archiveType: 'zip',
        url:      'https://github.com/projectdiscovery/naabu/releases/download/v2.3.5/naabu_2.3.5_windows_amd64.zip',
        binaryInArchive: 'naabu.exe' },
    ],
  },
  {
    id:          'httpx',
    description: 'HTTP service probe + tech fingerprint',
    version:     'v1.6.9',
    binary:      'httpx',
    sources: [
      { platform: 'darwin-arm64', sha256: '', archiveType: 'zip',
        url:      'https://github.com/projectdiscovery/httpx/releases/download/v1.6.9/httpx_1.6.9_macOS_arm64.zip',
        binaryInArchive: 'httpx' },
      { platform: 'darwin-amd64', sha256: '', archiveType: 'zip',
        url:      'https://github.com/projectdiscovery/httpx/releases/download/v1.6.9/httpx_1.6.9_macOS_amd64.zip',
        binaryInArchive: 'httpx' },
      { platform: 'linux-amd64',  sha256: '', archiveType: 'zip',
        url:      'https://github.com/projectdiscovery/httpx/releases/download/v1.6.9/httpx_1.6.9_linux_amd64.zip',
        binaryInArchive: 'httpx' },
      { platform: 'linux-arm64',  sha256: '', archiveType: 'zip',
        url:      'https://github.com/projectdiscovery/httpx/releases/download/v1.6.9/httpx_1.6.9_linux_arm64.zip',
        binaryInArchive: 'httpx' },
      { platform: 'windows-amd64', sha256: '', archiveType: 'zip',
        url:      'https://github.com/projectdiscovery/httpx/releases/download/v1.6.9/httpx_1.6.9_windows_amd64.zip',
        binaryInArchive: 'httpx.exe' },
    ],
  },
  {
    id:          'nuclei',
    description: 'CVE template scanner',
    version:     'v3.3.7',
    binary:      'nuclei',
    postInstall: 'nuclei-templates',
    sources: [
      { platform: 'darwin-arm64', sha256: '', archiveType: 'zip',
        url:      'https://github.com/projectdiscovery/nuclei/releases/download/v3.3.7/nuclei_3.3.7_macOS_arm64.zip',
        binaryInArchive: 'nuclei' },
      { platform: 'darwin-amd64', sha256: '', archiveType: 'zip',
        url:      'https://github.com/projectdiscovery/nuclei/releases/download/v3.3.7/nuclei_3.3.7_macOS_amd64.zip',
        binaryInArchive: 'nuclei' },
      { platform: 'linux-amd64',  sha256: '', archiveType: 'zip',
        url:      'https://github.com/projectdiscovery/nuclei/releases/download/v3.3.7/nuclei_3.3.7_linux_amd64.zip',
        binaryInArchive: 'nuclei' },
      { platform: 'linux-arm64',  sha256: '', archiveType: 'zip',
        url:      'https://github.com/projectdiscovery/nuclei/releases/download/v3.3.7/nuclei_3.3.7_linux_arm64.zip',
        binaryInArchive: 'nuclei' },
      { platform: 'windows-amd64', sha256: '', archiveType: 'zip',
        url:      'https://github.com/projectdiscovery/nuclei/releases/download/v3.3.7/nuclei_3.3.7_windows_amd64.zip',
        binaryInArchive: 'nuclei.exe' },
    ],
  },
  {
    id:          'subfinder',
    description: 'Passive subdomain discovery',
    version:     'v2.6.7',
    binary:      'subfinder',
    sources: [
      { platform: 'darwin-arm64', sha256: '', archiveType: 'zip',
        url:      'https://github.com/projectdiscovery/subfinder/releases/download/v2.6.7/subfinder_2.6.7_macOS_arm64.zip',
        binaryInArchive: 'subfinder' },
      { platform: 'darwin-amd64', sha256: '', archiveType: 'zip',
        url:      'https://github.com/projectdiscovery/subfinder/releases/download/v2.6.7/subfinder_2.6.7_macOS_amd64.zip',
        binaryInArchive: 'subfinder' },
      { platform: 'linux-amd64',  sha256: '', archiveType: 'zip',
        url:      'https://github.com/projectdiscovery/subfinder/releases/download/v2.6.7/subfinder_2.6.7_linux_amd64.zip',
        binaryInArchive: 'subfinder' },
      { platform: 'linux-arm64',  sha256: '', archiveType: 'zip',
        url:      'https://github.com/projectdiscovery/subfinder/releases/download/v2.6.7/subfinder_2.6.7_linux_arm64.zip',
        binaryInArchive: 'subfinder' },
      { platform: 'windows-amd64', sha256: '', archiveType: 'zip',
        url:      'https://github.com/projectdiscovery/subfinder/releases/download/v2.6.7/subfinder_2.6.7_windows_amd64.zip',
        binaryInArchive: 'subfinder.exe' },
    ],
  },
  {
    id:          'ffuf',
    description: 'Web fuzzing / directory busting',
    version:     'v2.1.0',
    binary:      'ffuf',
    sources: [
      { platform: 'darwin-arm64', sha256: '', archiveType: 'tar.gz',
        url:      'https://github.com/ffuf/ffuf/releases/download/v2.1.0/ffuf_2.1.0_macOS_arm64.tar.gz',
        binaryInArchive: 'ffuf' },
      { platform: 'darwin-amd64', sha256: '', archiveType: 'tar.gz',
        url:      'https://github.com/ffuf/ffuf/releases/download/v2.1.0/ffuf_2.1.0_macOS_amd64.tar.gz',
        binaryInArchive: 'ffuf' },
      { platform: 'linux-amd64',  sha256: '', archiveType: 'tar.gz',
        url:      'https://github.com/ffuf/ffuf/releases/download/v2.1.0/ffuf_2.1.0_linux_amd64.tar.gz',
        binaryInArchive: 'ffuf' },
      { platform: 'linux-arm64',  sha256: '', archiveType: 'tar.gz',
        url:      'https://github.com/ffuf/ffuf/releases/download/v2.1.0/ffuf_2.1.0_linux_arm64.tar.gz',
        binaryInArchive: 'ffuf' },
      { platform: 'windows-amd64', sha256: '', archiveType: 'zip',
        url:      'https://github.com/ffuf/ffuf/releases/download/v2.1.0/ffuf_2.1.0_windows_amd64.zip',
        binaryInArchive: 'ffuf.exe' },
    ],
  },
];
