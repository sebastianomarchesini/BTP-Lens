import '@testing-library/jest-dom/vitest';
// Same offline configuration as the report: no CDN fonts or locale data.
import '../ui5/setup';
import { cleanup } from '@testing-library/react';
import { afterEach, vi } from 'vitest';

// jsdom lacks a few browser APIs that UI5 and the charts use.
class ResizeObserverStub {
  observe(): void {}
  unobserve(): void {}
  disconnect(): void {}
}
globalThis.ResizeObserver ??= ResizeObserverStub;

// The charts measure label widths on a 2D canvas, which jsdom does not provide.
HTMLCanvasElement.prototype.getContext = function getContext() {
  return {
    font: '',
    measureText: (text: string) => ({ width: text.length * 7 }),
  } as unknown as CanvasRenderingContext2D;
} as unknown as typeof HTMLCanvasElement.prototype.getContext;

if (typeof window.matchMedia !== 'function') {
  window.matchMedia = (query: string): MediaQueryList => ({
    matches: false,
    media: query,
    onchange: null,
    addEventListener: () => {},
    removeEventListener: () => {},
    addListener: () => {},
    removeListener: () => {},
    dispatchEvent: () => false,
  });
}

afterEach(() => {
  cleanup();
  vi.unstubAllEnvs();
  document.getElementById('btp-lens-data')?.remove();
  window.location.hash = '';
});
