import { describe, expect, it } from 'vitest';
import { openInBrowser, windowsOpenCommand } from '../../src/guided/open.js';

describe('openInBrowser', () => {
  it('hands Windows a PowerShell literal, so cmd metacharacters in a URL or path are inert', () => {
    const [command, args] = windowsOpenCommand("https://login.cf.example.org/x&calc'|del *");
    expect(command).toBe('powershell.exe');
    expect(args).toContain('-EncodedCommand');
    const script = Buffer.from(args.at(-1) ?? '', 'base64').toString('utf16le');
    expect(script).toBe("Start-Process -FilePath 'https://login.cf.example.org/x&calc''|del *'");
  });

  it.skipIf(process.platform === 'win32')(
    'reports false when no opener can be started',
    async () => {
      // powershell.exe does not exist on POSIX hosts: the spawn fails at once.
      expect(await openInBrowser('https://example.org/', 'win32', 200)).toBe(false);
    },
  );
});
