import { describe, expect, it } from 'vitest';
import { buildpackOf, modulePathOf, parseMta } from '../../../../src/collectors/project/mta.js';
import { parsePackageJson, rangeOf } from '../../../../src/collectors/project/packageJson.js';
import {
  isLogoutRoute,
  parseXsApp,
  targetHintOf,
} from '../../../../src/collectors/project/xsApp.js';
import { parseXsSecurity } from '../../../../src/collectors/project/xsSecurity.js';

describe('package.json', () => {
  it('keeps the name, dependency names with registry ranges, and the node engine', () => {
    const result = parsePackageJson(
      JSON.stringify({
        name: 'acme-incidents',
        author: 'Jane Poison <jane.poison@example.com>',
        repository: 'https://POISON_repo_token@github.com/acme/x.git',
        dependencies: {
          '@sap/cds': '^9',
          express: '>=4.0.0 <5',
          'poison-git': 'git+https://POISON_git_token@github.com/acme/private.git',
          'poison-file': 'file:/Users/poison-user/lib',
          'poison-alias': 'npm:@poison-scope/private@1.0.0',
          'not a name': '1.0.0',
        },
        devDependencies: { vitest: '~3' },
        engines: { node: '>=22' },
        scripts: { start: 'POISON_script' },
        cds: { requires: { auth: 'mocked' } },
      }),
    );
    expect(result?.packageJson).toEqual({
      present: true,
      name: 'acme-incidents',
      dependencies: [
        { name: '@sap/cds', range: '^9' },
        { name: 'express', range: '>=4.0.0 <5' },
        { name: 'poison-git', range: '[non-registry]' },
        { name: 'poison-file', range: '[non-registry]' },
        { name: 'poison-alias', range: '[non-registry]' },
      ],
      devDependencies: [{ name: 'vitest', range: '~3' }],
      nodeEngine: '>=22',
    });
    expect(result?.cds).toEqual({ requires: { auth: 'mocked' } });
    expect(JSON.stringify(result?.packageJson)).not.toContain('POISON');
    expect(JSON.stringify(result?.packageJson)).not.toContain('poison-user');
  });

  it('rejects non-objects and invalid names', () => {
    expect(parsePackageJson('[]')).toBeNull();
    expect(parsePackageJson('not json')).toBeNull();
    expect(
      parsePackageJson('{ "name": "Has Space", "engines": { "node": 22 } }')?.packageJson,
    ).toMatchObject({
      name: null,
      nodeEngine: '[non-registry]',
    });
    expect(rangeOf('^1.2.3 || >=2')).toBe('^1.2.3 || >=2');
    expect(rangeOf('https://example.com/x.tgz')).toBe('[non-registry]');
    expect(rangeOf(`^${'1'.repeat(70)}`)).toBe('[non-registry]');
  });
});

describe('mta.yaml', () => {
  const text = `ID: acme-incidents
version: 1.0.0
description: POISON_description
modules:
  - name: acme-incidents-srv
    type: nodejs
    path: ./gen/srv/
    parameters:
      buildpack: https://poison-bp:POISON_bp_token@github.com/acme/buildpack.git?ref=POISON_ref
      memory: 256M
    properties:
      APP_SECRET: POISON_property
    build-parameters:
      builder: POISON_builder
    provides:
      - name: srv-api
        properties:
          srv-url: POISON_url
    hooks:
      - name: before-start
        parameters:
          command: POISON_hook
    requires:
      - name: acme-incidents-auth
      - name: acme-incidents-db
        parameters:
          POISON_key: POISON_value
  - name: 'not a module name'
  - name: acme-incidents-ui
    path: ../outside
resources:
  - name: acme-incidents-auth
    type: org.cloudfoundry.managed-service
    parameters:
      service: xsuaa
      service-plan: application
      service-key:
        name: POISON-service-key
      config:
        xsappname: acme-\${org}
        tenant-mode: dedicated
        scopes:
          - name: $XSAPPNAME.admin
            description: POISON_scope_description
          - name: $XSAPPNAME.callback
            grant-as-authority-to-apps: ['$XSAPPNAME(application,POISON_app)']
        role-templates:
          - name: Admin
            scope-references: ['$XSAPPNAME.admin', 'not a scope']
        attributes:
          - name: region
  - name: acme-incidents-db
    type: com.sap.xs.hdi-container
    parameters:
      service: hana
      service-plan: hdi-shared
      config:
        database_id: 00000000-POIS-ON00-0000-000000000000
  - name: acme-incidents-destination
    parameters:
      service: destination
      config:
        init_data:
          instance:
            destinations:
              - URL: https://poison-internal.example.com
                Password: POISON_pw
`;

  it('reads the ID, modules, resources and the xsuaa config as a descriptor', () => {
    const result = parseMta(text, 'mta.yaml');
    expect(result?.mta).toEqual({
      file: 'mta.yaml',
      id: 'acme-incidents',
      modules: [
        {
          name: 'acme-incidents-srv',
          type: 'nodejs',
          path: 'gen/srv',
          buildpack: 'https://github.com/acme/buildpack.git',
          requires: ['acme-incidents-auth', 'acme-incidents-db'],
        },
        { name: 'acme-incidents-ui', type: null, path: null, buildpack: null, requires: [] },
      ],
      resources: [
        {
          name: 'acme-incidents-auth',
          type: 'org.cloudfoundry.managed-service',
          service: 'xsuaa',
          plan: 'application',
        },
        {
          name: 'acme-incidents-db',
          type: 'com.sap.xs.hdi-container',
          service: 'hana',
          plan: 'hdi-shared',
        },
        { name: 'acme-incidents-destination', type: null, service: 'destination', plan: null },
      ],
    });
    expect(result?.xsSecurity).toEqual([
      {
        file: 'mta.yaml',
        source: 'mta.yaml',
        scopes: [
          { name: '$XSAPPNAME.admin', grantedToApps: false },
          { name: '$XSAPPNAME.callback', grantedToApps: true },
        ],
        roleTemplates: [{ name: 'Admin', scopeReferences: ['$XSAPPNAME.admin'] }],
        attributes: [],
      },
    ]);
    expect(JSON.stringify(result)).not.toMatch(/POISON|poison/);
  });

  it('rejects non-mapping documents and odd ids', () => {
    expect(parseMta('- a\n', 'mta.yaml')).toBeNull();
    expect(parseMta('ID: "has space"\n', 'mta.yml')?.mta).toEqual({
      file: 'mta.yml',
      id: null,
      modules: [],
      resources: [],
    });
    expect(buildpackOf('nodejs_buildpack')).toBe('nodejs_buildpack');
    expect(buildpackOf('')).toBeNull();
    expect(buildpackOf(`https://h.example.com/${'a'.repeat(300)}`)).toHaveLength(200);
  });

  it('keeps a buildpack name or an http(s)/git URL without credentials; never a local path', () => {
    expect(buildpackOf('sap_java_buildpack_jakarta')).toBe('sap_java_buildpack_jakarta');
    expect(buildpackOf('nodejs-buildpack-v1.8.40')).toBe('nodejs-buildpack-v1.8.40');
    expect(buildpackOf('git://u:p@github.com/acme/bp.git?ref=POISON_ref#x')).toBe(
      'git://github.com/acme/bp.git',
    );
    expect(buildpackOf('git+https://github.com/acme/bp.git')).toBe(
      'git+https://github.com/acme/bp.git',
    );
    expect(buildpackOf('/home/poison-user/POISON_bp_path/nodejs')).toBeNull();
    expect(buildpackOf('C:\\Users\\poison-user\\buildpacks')).toBeNull();
    expect(buildpackOf('../POISON_bp_path')).toBeNull();
    expect(buildpackOf('file:///home/poison-user/bp')).toBeNull();
    expect(buildpackOf('ssh://git@github.com/acme/bp.git')).toBeNull();
    expect(buildpackOf('a'.repeat(101))).toBeNull();
    expect(buildpackOf('name with space')).toBeNull();
    expect(buildpackOf(42)).toBeNull();
  });

  it('applies YAML merge keys, as the MTA build tool does', () => {
    const result = parseMta(
      [
        '_defs:',
        '  base: &base',
        '    type: nodejs',
        '    path: srv',
        '    parameters:',
        '      buildpack: nodejs_buildpack',
        'modules:',
        '  - name: srv',
        '    <<: *base',
        '  - name: ui',
        '    <<: *base',
        '    type: html5',
      ].join('\n'),
      'mta.yaml',
    );
    expect(result?.mta.modules).toEqual([
      { name: 'srv', type: 'nodejs', path: 'srv', buildpack: 'nodejs_buildpack', requires: [] },
      { name: 'ui', type: 'html5', path: 'srv', buildpack: 'nodejs_buildpack', requires: [] },
    ]);
    expect(modulePathOf('./srv')).toBe('srv');
    expect(modulePathOf('/abs/srv')).toBeNull();
    expect(modulePathOf('../up')).toBeNull();
    expect(modulePathOf(3)).toBeNull();
  });
});

describe('xs-security.json', () => {
  it('keeps scope, role-template and attribute names only', () => {
    const result = parseXsSecurity(
      JSON.stringify({
        xsappname: 'POISON_app',
        'tenant-mode': 'dedicated',
        description: 'owner jane.poison@example.com',
        scopes: [
          { name: '$XSAPPNAME.admin', description: 'POISON_desc' },
          { name: '$XSAPPNAME.callback', 'granted-apps': ['$XSAPPNAME(application,POISON_app)'] },
          { name: '$XSAPPNAME.empty', 'granted-apps': [] },
          { name: 'bad scope name' },
        ],
        attributes: [{ name: 'region', valueType: 'string' }, { name: 'bad attr' }],
        'role-templates': [
          {
            name: 'Token_Exchange',
            'scope-references': ['uaa.user'],
            'foreign-scope-references': ['$XSAPPNAME(application,poison-foreign).read'],
          },
        ],
        'oauth2-configuration': { 'redirect-uris': ['https://poison-redirect.example.com/**'] },
        authorities: ['$XSAPPNAME.POISON_authority'],
      }),
      'xs-security.json',
    );
    expect(result).toEqual({
      file: 'xs-security.json',
      source: 'xs-security.json',
      scopes: [
        { name: '$XSAPPNAME.admin', grantedToApps: false },
        { name: '$XSAPPNAME.callback', grantedToApps: true },
        { name: '$XSAPPNAME.empty', grantedToApps: false },
      ],
      roleTemplates: [{ name: 'Token_Exchange', scopeReferences: ['uaa.user'] }],
      attributes: ['region'],
    });
    expect(JSON.stringify(result)).not.toMatch(/POISON|poison/);
    expect(parseXsSecurity('[]', 'xs-security.json')).toBeNull();
  });
});

describe('xs-app.json', () => {
  it('keeps route sources, auth, csrf and a target hint; never a destination name', () => {
    const result = parseXsApp(
      JSON.stringify({
        welcomeFile: '/POISON_welcome.html',
        authenticationMethod: 'route',
        logout: { logoutEndpoint: '/do/logout', logoutPage: '/logout.html' },
        routes: [
          {
            source: '^/odata/(.*)$',
            destination: 'srv-api',
            authenticationType: 'xsuaa',
            csrfProtection: false,
          },
          {
            source: '^/public/(.*)$',
            destination: 'POISON-destination',
            authenticationType: 'none',
          },
          { source: '^/resources/(.*)$', destination: 'ui5', authenticationType: 'none' },
          { source: '^/cdn/(.*)$', destination: 'my-sapui5-cdn' },
          { source: '^/logout.html$', localDir: 'POISON-dir', authenticationType: 'none' },
          { source: '^(.*)$', service: 'html5-apps-repo-rt', authenticationType: 'ias' },
          { source: '^/x$', destination: 'backend-POISON', authenticationType: 'saml' },
          {
            source: '^/basic$',
            destination: 'other-thing',
            authenticationType: 'basic',
            csrfProtection: true,
          },
          { source: '^/none$' },
          { destination: 'no-source' },
          'not a route',
        ],
      }),
      'app/xs-app.json',
    );
    expect(result).toEqual({
      file: 'app/xs-app.json',
      authenticationMethod: 'route',
      routes: [
        {
          source: '^/odata/(.*)$',
          authenticationType: 'xsuaa',
          csrfProtection: false,
          target: 'destination',
          targetHint: 'api',
          isLogoutPage: false,
        },
        {
          source: '^/public/(.*)$',
          authenticationType: 'none',
          csrfProtection: null,
          target: 'destination',
          targetHint: 'other',
          isLogoutPage: false,
        },
        {
          source: '^/resources/(.*)$',
          authenticationType: 'none',
          csrfProtection: null,
          target: 'destination',
          targetHint: 'ui5-cdn',
          isLogoutPage: false,
        },
        {
          source: '^/cdn/(.*)$',
          authenticationType: null,
          csrfProtection: null,
          target: 'destination',
          targetHint: 'ui5-cdn',
          isLogoutPage: false,
        },
        {
          source: '^/logout.html$',
          authenticationType: 'none',
          csrfProtection: null,
          target: 'localDir',
          targetHint: 'other',
          isLogoutPage: true,
        },
        {
          source: '^(.*)$',
          authenticationType: 'ias',
          csrfProtection: null,
          target: 'service',
          targetHint: 'html5-repo',
          isLogoutPage: false,
        },
        {
          source: '^/x$',
          authenticationType: 'other',
          csrfProtection: null,
          target: 'destination',
          targetHint: 'api',
          isLogoutPage: false,
        },
        {
          source: '^/basic$',
          authenticationType: 'basic',
          csrfProtection: true,
          target: 'destination',
          targetHint: 'other',
          isLogoutPage: false,
        },
        {
          source: '^/none$',
          authenticationType: null,
          csrfProtection: null,
          target: 'unknown',
          targetHint: 'other',
          isLogoutPage: false,
        },
      ],
    });
    expect(JSON.stringify(result)).not.toMatch(/POISON|srv-api|html5-apps|my-sapui5/);
  });

  it('maps the authentication method and compares the logout page literally', () => {
    expect(parseXsApp('{ "authenticationMethod": "none" }', 'x')?.authenticationMethod).toBe(
      'none',
    );
    expect(parseXsApp('{ "authenticationMethod": "custom" }', 'x')?.authenticationMethod).toBe(
      'other',
    );
    expect(parseXsApp('{}', 'x')?.authenticationMethod).toBeNull();
    expect(parseXsApp('"x"', 'x')).toBeNull();
    expect(isLogoutRoute('^/logout\\.html$', '/logout.html')).toBe(true);
    expect(isLogoutRoute('/logout.html', '/logout.html')).toBe(true);
    expect(isLogoutRoute('^/logout/(.*)$', '/logout.html')).toBe(false);
    expect(isLogoutRoute('^/logout.html$', undefined)).toBe(false);
    expect(targetHintOf('ui5')).toBe('ui5-cdn');
    expect(targetHintOf('ui5-destination')).toBe('other');
    expect(targetHintOf('my-backend')).toBe('api');
    const long = `^/${'a'.repeat(300)}$`;
    expect(
      parseXsApp(JSON.stringify({ routes: [{ source: long }] }), 'x')?.routes[0]?.source,
    ).toHaveLength(200);
  });
});
