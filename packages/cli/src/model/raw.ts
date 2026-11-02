import { z } from 'zod';
import { RelativePathSchema } from './paths.js';

/*
 * Normalized, sanitized raw data collected from the CF API or from a local
 * project directory. This is what the analyzers read, and what
 * `report --from snapshot.json` re-analyzes offline. Only allow-listed fields
 * are kept: zod strips every unknown key, so user identities, env values and
 * credentials cannot slip into a snapshot.
 */

const Timestamp = z.iso.datetime({ offset: true });

export const LifecycleTypeSchema = z.enum(['buildpack', 'cnb', 'docker', 'unknown']);
export type LifecycleType = z.infer<typeof LifecycleTypeSchema>;

export const RawOrgSchema = z.object({
  guid: z.string(),
  name: z.string(),
});
export type RawOrg = z.infer<typeof RawOrgSchema>;

export const RawSpaceSchema = z.object({
  guid: z.string(),
  name: z.string(),
  orgGuid: z.string(),
});
export type RawSpace = z.infer<typeof RawSpaceSchema>;

export const RawAppSchema = z.object({
  guid: z.string(),
  name: z.string(),
  spaceGuid: z.string(),
  state: z.enum(['STARTED', 'STOPPED']),
  createdAt: Timestamp,
  updatedAt: Timestamp,
  lifecycleType: LifecycleTypeSchema,
  /** Buildpacks requested for the app (names, or URLs with credentials removed). */
  buildpacks: z.array(z.string()),
  stack: z.string().nullable(),
});
export type RawApp = z.infer<typeof RawAppSchema>;

export const RawDetectedBuildpackSchema = z.object({
  name: z.string(),
  buildpackName: z.string().nullable(),
  version: z.string().nullable(),
  detectOutput: z.string().nullable(),
});
export type RawDetectedBuildpack = z.infer<typeof RawDetectedBuildpackSchema>;

export const RawDropletSchema = z.object({
  guid: z.string(),
  appGuid: z.string(),
  state: z.string(),
  createdAt: Timestamp,
  updatedAt: Timestamp,
  lifecycleType: LifecycleTypeSchema,
  stack: z.string().nullable(),
  buildpacks: z.array(RawDetectedBuildpackSchema),
  /** Docker image reference for docker droplets (credentials removed). */
  image: z.string().nullable(),
});
export type RawDroplet = z.infer<typeof RawDropletSchema>;

/*
 * Local project (`btp-lens project`). Every field is an allow-listed
 * structural fact: identifiers, relative file names, counts and booleans.
 * Never file contents, CSV values, user names, passwords, descriptions,
 * URLs with credentials or absolute paths. Every string has a maximum
 * length, every array a maximum size, and enum-shaped values have an
 * `other` bucket, so a hostile project cannot grow or poison a snapshot.
 */

/** Project ids: the mta ID, the package name without scope, or the directory name. */
export const PROJECT_ID_PATTERN = /^[A-Za-z0-9._-]{1,64}$/;
/** Names of entities, services, scopes, roles, attributes, modules, resources, columns and targets. */
export const IDENTIFIER_PATTERN = /^[A-Za-z_$][\w.$:-]{0,127}$/;
/** A role name as it may appear in `@requires` or `@restrict.to`. */
export const ROLE_PATTERN = /^[A-Za-z0-9_.$:-]{1,64}$/;
/** npm package names, as `package.json#name` and dependency keys. */
export const PACKAGE_NAME_PATTERN = /^(@[a-z0-9._-]+\/)?[a-z0-9._-]{1,214}$/i;
/** A dependency range or engine range; anything else is stored as this placeholder. */
export const NON_REGISTRY_RANGE = '[non-registry]';
export const RANGE_PATTERN = /^[\s0-9A-Za-z.*^~<>=|+-]{0,64}$/;

const Identifier = z.string().regex(IDENTIFIER_PATTERN);
const Role = z.string().regex(ROLE_PATTERN);
const Line = z.number().int().positive();
const Count = z.number().int().nonnegative();
const Roles = z.array(Role).max(50);

export const CdsAuthKindSchema = z.enum([
  'mocked',
  'dummy',
  'basic',
  'xsuaa',
  'ias',
  'jwt',
  'ams',
  'other',
]);
export type CdsAuthKind = z.infer<typeof CdsAuthKindSchema>;

export const CdsAuditLogKindSchema = z.enum([
  'audit-log-to-restv2',
  'audit-log-to-alsng',
  'audit-log-to-console',
  'audit-log-to-library',
  'other',
]);
export type CdsAuditLogKind = z.infer<typeof CdsAuditLogKindSchema>;

/** The parts of the effective cds configuration a rule may look at, per profile. */
export const CdsViewSchema = z.object({
  /** `requires.auth` as a string, or `requires.auth.kind`; unknown strings become `other`. */
  authKind: CdsAuthKindSchema.nullable(),
  /** Number of keys in `requires.auth.users`; nothing else of `users` is read. */
  mockedUsers: Count,
  /** How many of those users carry a `password` key (the value is never read). */
  mockedUsersWithPassword: Count,
  restrictAllServices: z.boolean().nullable(),
  auditLogKind: CdsAuditLogKindSchema.nullable(),
  /** `requires['audit-log']` present in any shape, including `true`. */
  auditLogConfigured: z.boolean(),
});
export type CdsView = z.infer<typeof CdsViewSchema>;

export const CdsSourceSchema = z.enum(['.cdsrc.yaml', '.cdsrc.json', 'package.json']);
export type CdsSource = z.infer<typeof CdsSourceSchema>;

export const UnreadableKindSchema = z.enum([
  'json',
  'yaml',
  'csv',
  'cds',
  'html',
  'binary',
  'too-large',
]);
export type UnreadableKind = z.infer<typeof UnreadableKindSchema>;

export const RawUnreadableSchema = z.object({
  file: RelativePathSchema,
  kind: UnreadableKindSchema,
});
export type RawUnreadable = z.infer<typeof RawUnreadableSchema>;

export const RawDependencySchema = z.object({
  name: z.string().regex(PACKAGE_NAME_PATTERN),
  /** The range as written when it is registry-shaped, else `[non-registry]`. */
  range: z.string().max(64),
});
export type RawDependency = z.infer<typeof RawDependencySchema>;

export const RawPackageJsonSchema = z.object({
  present: z.boolean(),
  name: z.string().regex(PACKAGE_NAME_PATTERN).nullable(),
  dependencies: z.array(RawDependencySchema).max(500),
  devDependencies: z.array(RawDependencySchema).max(500),
  nodeEngine: z.string().max(64).nullable(),
});
export type RawPackageJson = z.infer<typeof RawPackageJsonSchema>;

export const RawMtaModuleSchema = z.object({
  name: Identifier,
  type: Identifier.nullable(),
  path: RelativePathSchema.nullable(),
  /** `parameters.buildpack` with credentials and query removed. */
  buildpack: z.string().max(200).nullable(),
  /** Names of the required resources. */
  requires: z.array(Identifier).max(50),
});
export type RawMtaModule = z.infer<typeof RawMtaModuleSchema>;

export const RawMtaResourceSchema = z.object({
  name: Identifier,
  type: Identifier.nullable(),
  service: Identifier.nullable(),
  plan: Identifier.nullable(),
});
export type RawMtaResource = z.infer<typeof RawMtaResourceSchema>;

export const RawMtaSchema = z.object({
  file: z.enum(['mta.yaml', 'mta.yml']),
  id: z.string().regex(PROJECT_ID_PATTERN).nullable(),
  modules: z.array(RawMtaModuleSchema).max(200),
  resources: z.array(RawMtaResourceSchema).max(200),
});
export type RawMta = z.infer<typeof RawMtaSchema>;

export const RawXsSecurityScopeSchema = z.object({
  name: Identifier,
  /** Has `granted-apps` or `grant-as-authority-to-apps`. */
  grantedToApps: z.boolean(),
});
export type RawXsSecurityScope = z.infer<typeof RawXsSecurityScopeSchema>;

export const RawXsSecurityRoleTemplateSchema = z.object({
  name: Identifier,
  scopeReferences: z.array(Identifier).max(500),
});
export type RawXsSecurityRoleTemplate = z.infer<typeof RawXsSecurityRoleTemplateSchema>;

/** An XSUAA descriptor: xs-security.json, or the `config` of an xsuaa resource in mta.yaml. */
export const RawXsSecuritySchema = z.object({
  file: RelativePathSchema,
  source: z.enum(['xs-security.json', 'mta.yaml']),
  scopes: z.array(RawXsSecurityScopeSchema).max(500),
  roleTemplates: z.array(RawXsSecurityRoleTemplateSchema).max(500),
  /** Attribute names only. */
  attributes: z.array(Identifier).max(500),
});
export type RawXsSecurity = z.infer<typeof RawXsSecuritySchema>;

export const XsAppAuthenticationTypeSchema = z.enum(['xsuaa', 'ias', 'basic', 'none', 'other']);
export type XsAppAuthenticationType = z.infer<typeof XsAppAuthenticationTypeSchema>;

export const XsAppRouteTargetSchema = z.enum(['destination', 'service', 'localDir', 'unknown']);
export type XsAppRouteTarget = z.infer<typeof XsAppRouteTargetSchema>;

export const XsAppTargetHintSchema = z.enum(['ui5-cdn', 'html5-repo', 'api', 'other']);
export type XsAppTargetHint = z.infer<typeof XsAppTargetHintSchema>;

export const RawXsAppRouteSchema = z.object({
  /** The route regex as written. */
  source: z.string().max(200),
  authenticationType: XsAppAuthenticationTypeSchema.nullable(),
  csrfProtection: z.boolean().nullable(),
  target: XsAppRouteTargetSchema,
  /**
   * Computed from the destination or service name, which is not stored:
   * `ui5-cdn` for /^ui5$|sapui5|cdn/i, `html5-repo` for html5-apps-repo-rt,
   * `api` for /srv|api|backend/i, else `other`.
   */
  targetHint: XsAppTargetHintSchema,
  /** The source matches `logout.logoutPage`. */
  isLogoutPage: z.boolean(),
});
export type RawXsAppRoute = z.infer<typeof RawXsAppRouteSchema>;

export const RawXsAppSchema = z.object({
  file: RelativePathSchema,
  authenticationMethod: z.enum(['route', 'none', 'other']).nullable(),
  routes: z.array(RawXsAppRouteSchema).max(200),
});
export type RawXsApp = z.infer<typeof RawXsAppSchema>;

export const RawCdsUsingSchema = z.object({
  alias: Identifier,
  target: Identifier,
});
export type RawCdsUsing = z.infer<typeof RawCdsUsingSchema>;

export const RawCdsServiceEntitySchema = z.object({
  name: Identifier,
  line: Line,
  requires: Roles,
  restrictTo: Roles,
  readonly: z.boolean(),
  /** The `as projection on` target as written (alias not resolved). */
  projectionOf: Identifier.nullable(),
});
export type RawCdsServiceEntity = z.infer<typeof RawCdsServiceEntitySchema>;

export const RawCdsActionSchema = z.object({
  name: Identifier,
  line: Line,
  requires: Roles,
  restrictTo: Roles,
});
export type RawCdsAction = z.infer<typeof RawCdsActionSchema>;

export const RawCdsServiceSchema = z.object({
  name: Identifier,
  line: Line,
  requires: Roles,
  restrictTo: Roles,
  /** `@protocol: 'none'`: an internal service with no HTTP endpoint. */
  protocolNone: z.boolean(),
  /** `@cds.external`: an imported remote service. */
  external: z.boolean(),
  entities: z.array(RawCdsServiceEntitySchema).max(2000),
  actions: z.array(RawCdsActionSchema).max(500),
});
export type RawCdsService = z.infer<typeof RawCdsServiceSchema>;

export const RawCdsAssociationSchema = z.object({
  field: Identifier,
  /** The association target as written (alias not resolved). */
  target: Identifier,
});
export type RawCdsAssociation = z.infer<typeof RawCdsAssociationSchema>;

/** A top-level or namespaced entity (not one inside a service block). */
export const RawCdsEntitySchema = z.object({
  name: Identifier,
  line: Line,
  fields: z.array(Identifier).max(200),
  /** `@PersonalData` on the entity header or on any element inline. */
  personalData: z.boolean(),
  associations: z.array(RawCdsAssociationSchema).max(200),
});
export type RawCdsEntity = z.infer<typeof RawCdsEntitySchema>;

export const RawCdsAnnotateSchema = z.object({
  /** The `annotate TARGET` as written (alias not resolved). */
  target: Identifier,
  line: Line,
  /** `@PersonalData` anywhere in the statement (header or element block). */
  personalData: z.boolean(),
  requires: Roles,
  restrictTo: Roles,
});
export type RawCdsAnnotate = z.infer<typeof RawCdsAnnotateSchema>;

export const RawCdsFileSchema = z.object({
  file: RelativePathSchema,
  /** `using X as Y from` within this file (identifiers only). */
  usings: z.array(RawCdsUsingSchema).max(500),
  services: z.array(RawCdsServiceSchema).max(500),
  entities: z.array(RawCdsEntitySchema).max(2000),
  annotates: z.array(RawCdsAnnotateSchema).max(2000),
});
export type RawCdsFile = z.infer<typeof RawCdsFileSchema>;

export const SeedSensitiveKindSchema = z.enum(['card', 'iban', 'secret']);
export type SeedSensitiveKind = z.infer<typeof SeedSensitiveKindSchema>;

export const RawSeedSensitiveColumnSchema = z.object({
  /** 1-based position of the column in the header; the name itself is never stored. */
  columnIndex: Line,
  kind: SeedSensitiveKindSchema,
  rowsMatching: Count,
});
export type RawSeedSensitiveColumn = z.infer<typeof RawSeedSensitiveColumnSchema>;

/** A seed CSV: header shape and value checks only; no header names or values are stored, only column positions. */
export const RawSeedDataSchema = z.object({
  file: RelativePathSchema,
  columnCount: Count,
  /** The header had a field that is not identifier-shaped, so no values were checked. */
  headerRejected: z.boolean(),
  rowsChecked: Count,
  sensitiveColumns: z.array(RawSeedSensitiveColumnSchema).max(200),
});
export type RawSeedData = z.infer<typeof RawSeedDataSchema>;

/** An `*.mtar` seen by the walk; only `stat`ed, never opened. */
export const RawArchiveSchema = z.object({
  file: RelativePathSchema,
  bytes: Count,
  /** Matched by a .gitignore pattern. */
  ignored: z.boolean(),
});
export type RawArchive = z.infer<typeof RawArchiveSchema>;

export const Ui5VersionFormSchema = z.enum(['specific', 'evergreen', 'latest', 'none']);
export type Ui5VersionForm = z.infer<typeof Ui5VersionFormSchema>;

/** A SAPUI5 bootstrap script in an HTML file. */
export const RawHtmlBootstrapSchema = z.object({
  file: RelativePathSchema,
  line: Line,
  /**
   * Of an http(s) URL the origin and path only (no userinfo, query or fragment);
   * of a relative src the file name only; `[non-http]` for other schemes.
   */
  src: z.string().max(200),
  external: z.boolean(),
  /** An `integrity` attribute is present (its value is never stored). */
  integrity: z.boolean(),
  versionForm: Ui5VersionFormSchema,
  /** Under a `test/` directory, or named like flpSandbox.html / *.qunit.html. */
  testPage: z.boolean(),
});
export type RawHtmlBootstrap = z.infer<typeof RawHtmlBootstrapSchema>;

export const RawProjectSchema = z.object({
  id: z.string().regex(PROJECT_ID_PATTERN),
  /** Which optional cds config sources existed and were read. */
  sourcesRead: z.array(CdsSourceSchema).max(3),
  /** Files the collector opened (allow-listed names only), sorted. */
  files: z.array(RelativePathSchema).max(500),
  filesTruncated: z.boolean(),
  /** How many files inside the project the collector opened (listed or unreadable), whatever the listing cap. */
  filesOpened: Count,
  unreadable: z.array(RawUnreadableSchema).max(200),
  /** A `.git` entry exists in the root or one of its ancestors (lstat only, never read). */
  repository: z.boolean(),
  gitIgnore: z.object({ present: z.boolean() }),
  packageJson: RawPackageJsonSchema,
  cds: z.object({
    /** Effective config per profile, after merging the sources in cds order and applying `[profile]` blocks. */
    effective: z.object({
      development: CdsViewSchema,
      production: CdsViewSchema,
    }),
  }),
  mta: RawMtaSchema.nullable(),
  xsSecurity: z.array(RawXsSecuritySchema).max(100),
  xsApps: z.array(RawXsAppSchema).max(100),
  cdsFiles: z.array(RawCdsFileSchema).max(2000),
  seedData: z.array(RawSeedDataSchema).max(500),
  archives: z.array(RawArchiveSchema).max(200),
  html: z.array(RawHtmlBootstrapSchema).max(200),
});
export type RawProject = z.infer<typeof RawProjectSchema>;

export const RawDataSchema = z.object({
  orgs: z.array(RawOrgSchema),
  spaces: z.array(RawSpaceSchema),
  apps: z.array(RawAppSchema),
  /** Current droplet per app; absent when the droplet collector was skipped. */
  droplets: z.array(RawDropletSchema),
  /** Local projects (`btp-lens project`); empty for a CF scan and in snapshots written before 0.2. */
  projects: z.array(RawProjectSchema).default([]),
});
export type RawData = z.infer<typeof RawDataSchema>;
