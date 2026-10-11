import { spawn } from 'node:child_process';

export type OpenInBrowser = (target: string) => Promise<boolean>;

/**
 * On Windows the target goes to PowerShell as a single-quoted literal inside an
 * encoded command. `cmd /c start` would interpret & | ^ % in a path or URL,
 * and the passcode URL comes from the CF API, not from us.
 */
export function windowsOpenCommand(target: string): [command: string, args: string[]] {
  const script = `Start-Process -FilePath '${target.replace(/'/g, "''")}'`;
  return [
    'powershell.exe',
    [
      '-NoProfile',
      '-NonInteractive',
      '-ExecutionPolicy',
      'Bypass',
      '-EncodedCommand',
      Buffer.from(script, 'utf16le').toString('base64'),
    ],
  ];
}

/**
 * Opens a local file or an https URL with the OS default handler. Arguments
 * are passed as an array, never through a shell string. Resolves false when no
 * opener is available or it fails quickly (headless hosts, CI, SSH, WSL
 * without a browser bridge), so the caller can tell the user to open the file
 * by hand instead of claiming it was opened.
 */
export function openInBrowser(
  target: string,
  platform: NodeJS.Platform = process.platform,
  graceMs = 2500,
): Promise<boolean> {
  const [command, args] =
    platform === 'darwin'
      ? ['open', [target]]
      : platform === 'win32'
        ? windowsOpenCommand(target)
        : ['xdg-open', [target]];
  return new Promise<boolean>((resolve) => {
    let child;
    try {
      child = spawn(command, args, { detached: true, stdio: 'ignore', windowsHide: true });
    } catch {
      resolve(false);
      return;
    }
    let settled = false;
    const settle = (ok: boolean) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve(ok);
    };
    // Openers return once the browser is launched; a non-zero exit means it could not.
    const timer = setTimeout(() => {
      child.unref();
      settle(true);
    }, graceMs);
    child.once('error', () => settle(false));
    child.once('exit', (code) => settle(code === 0));
  });
}
