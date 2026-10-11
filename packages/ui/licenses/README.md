License texts for bundled packages whose npm tarball does not include one, and
for code vendored inside a package under a different license. The report build
(`vite.config.ts`, `embedLicenses` and `VENDORED_NOTICES`) reads them from here.

- `victory-vendor.LICENSE`: copied from https://github.com/FormidableLabs/victory/blob/main/LICENSE.txt
- `@ui5__webcomponents-base.preact.LICENSE`: the MIT license of Preact
  (https://github.com/preactjs/preact/blob/main/LICENSE), which
  `@ui5/webcomponents-base` vendors under `dist/thirdparty/preact/` without
  shipping the notice.

The Unicode CLDR notice for `@ui5/webcomponents-localization` is read from the
package itself (`dist/generated/assets/cldr/Unicode-Data-Files-LICENSE.txt`).
