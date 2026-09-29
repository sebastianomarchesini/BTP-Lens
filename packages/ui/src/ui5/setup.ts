/**
 * Makes UI5 Web Components work fully offline, as the single-file report
 * requires: fonts, the dark theme and locale data are bundled, and nothing is
 * fetched from a CDN (by default UI5 loads fonts and CLDR data from
 * cdn.jsdelivr.net). Import this module before any UI5 component.
 */
import { registerLocaleDataLoader } from '@ui5/webcomponents-base/dist/asset-registries/LocaleData.js';
import { registerThemePropertiesLoader } from '@ui5/webcomponents-base/dist/asset-registries/Themes.js';
import { setDefaultFontLoading } from '@ui5/webcomponents-base/dist/config/Fonts.js';
import fioriDark from '@ui5/webcomponents-fiori/dist/generated/assets/themes/sap_horizon_dark/parameters-bundle.css.json';
import cldrEn from '@ui5/webcomponents-localization/dist/generated/assets/cldr/en.json';
import baseDark from '@ui5/webcomponents-theming/dist/generated/assets/themes/sap_horizon_dark/parameters-bundle.css.json';
import mainDark from '@ui5/webcomponents/dist/generated/assets/themes/sap_horizon_dark/parameters-bundle.css.json';
import bold from '@sap-theming/theming-base-content/content/Base/baseLib/baseTheme/fonts/72-Bold.woff2';
import regular from '@sap-theming/theming-base-content/content/Base/baseLib/baseTheme/fonts/72-Regular.woff2';
import semibold from '@sap-theming/theming-base-content/content/Base/baseLib/baseTheme/fonts/72-Semibold.woff2';
import semiboldDuplex from '@sap-theming/theming-base-content/content/Base/baseLib/baseTheme/fonts/72-SemiboldDuplex.woff2';

setDefaultFontLoading(false);

// sap_horizon (light) is built into the components; register the dark theme.
// The package names and the "host" argument mirror UI5's own json-imports.
const DARK = 'sap_horizon_dark';
const load = (data: string) => () => Promise.resolve(data);
registerThemePropertiesLoader('@ui5/webcomponents-theming', DARK, load(baseDark));
registerThemePropertiesLoader('@ui5/webcomponents', DARK, load(mainDark), 'host');
registerThemePropertiesLoader('@ui5/webcomponents-fiori', DARK, load(fioriDark), 'host');

// Replaces UI5's default "en" loader, which fetches from a CDN.
registerLocaleDataLoader('en', () => Promise.resolve(cldrEn));

/** Latin subsets of the "72" typeface, under the family names UI5 uses. */
const FONT_FACES: [family: string, url: string, weight: string][] = [
  ['72', regular, '400'],
  ['72', semibold, '600'],
  ['72', bold, '700'],
  ['72-Bold', bold, '700'],
  ['72-Semibold', semibold, '600'],
  ['72-SemiboldDuplex', semiboldDuplex, '600'],
];

if (typeof FontFace !== 'undefined' && typeof document !== 'undefined') {
  for (const [family, url, weight] of FONT_FACES) {
    const face = new FontFace(family, `url(${url}) format('woff2')`, { weight, display: 'swap' });
    document.fonts.add(face);
    face.load().catch(() => {
      // Falls back to Arial/Helvetica, as the theme's font stack defines.
    });
  }
}
