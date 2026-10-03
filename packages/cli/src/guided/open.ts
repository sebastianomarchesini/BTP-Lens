import { spawn } from 'node:child_process';

export type OpenInBrowser = (path: string) => Promise<boolean>;

/**
 * Opens a local file with the OS default handler. Arguments are passed as an
 * array, never through a shell string, and the path is one BTP Lens built
 * itself. Returns false when no opener is available (headless hosts, CI).
 */
export function openInBrowser(path: string, platform: NodeJS.Platform = process.platform) {
  const [command, args] =
    platform === 'darwin'
      ? ['open', [path]]
      : platform === 'win32'
        ? ['cmd', ['/c', 'start', '', path]]
        : ['xdg-open', [path]];
  return new Promise<boolean>((resolve) => {
    let child;
    try {
      child = spawn(command, args, { detached: true, stdio: 'ignore', windowsHide: true });
    } catch {
      resolve(false);
      return;
    }
    child.once('error', () => resolve(false));
    child.once('spawn', () => {
      child.unref();
      resolve(true);
    });
  });
}
