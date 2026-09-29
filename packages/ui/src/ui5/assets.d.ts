// The UI5 theme bundles are JSON files that contain one CSS string.
declare module '*/parameters-bundle.css.json' {
  const css: string;
  export default css;
}

declare module '@ui5/webcomponents-localization/dist/generated/assets/cldr/en.json' {
  const cldr: Record<string, object | boolean | string>;
  export default cldr;
}
