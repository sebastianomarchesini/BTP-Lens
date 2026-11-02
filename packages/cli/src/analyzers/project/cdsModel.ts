import type {
  RawCdsAction,
  RawCdsAssociation,
  RawCdsFile,
  RawCdsServiceEntity,
  RawProject,
} from '../../model/raw.js';
import {
  PERSONAL_ENTITY_NAME,
  PSEUDO_ROLES,
  isStrongPersonalField,
  isWeakPersonalField,
} from './patterns.js';

/*
 * Pure views over the collected CDS facts. The collector stores names as
 * written; these helpers resolve `using … as` aliases and match
 * namespace-qualified names by suffix, so rules see one merged picture of a
 * service or an entity whatever file its annotations live in.
 */

/** Resolves a `using X as Y` alias: `Y` → `X`, `Y.Rest` → `X.Rest`. */
export function resolveTarget(file: RawCdsFile, target: string): string {
  for (const using of file.usings) {
    if (target === using.alias) return using.target;
    if (target.startsWith(`${using.alias}.`))
      return using.target + target.slice(using.alias.length);
  }
  return target;
}

/** Exact, or one is the namespace-qualified form of the other. */
export function namesMatch(candidate: string, name: string): boolean {
  return candidate === name || candidate.endsWith(`.${name}`) || name.endsWith(`.${candidate}`);
}

function sortedUnique(values: Iterable<string>): string[] {
  return [...new Set(values)].sort((a, b) => a.localeCompare(b));
}

interface ResolvedAnnotate {
  target: string;
  personalData: boolean;
  requires: string[];
  restrictTo: string[];
}

function resolvedAnnotates(project: RawProject): ResolvedAnnotate[] {
  return project.cdsFiles.flatMap((file) =>
    file.annotates.map((annotate) => ({
      target: resolveTarget(file, annotate.target),
      personalData: annotate.personalData,
      requires: annotate.requires,
      restrictTo: annotate.restrictTo,
    })),
  );
}

export interface EffectiveService {
  file: string;
  name: string;
  line: number;
  protocolNone: boolean;
  external: boolean;
  /** Merged from the service, its entities, its actions and every annotate on them. */
  requires: string[];
  restrictTo: string[];
  entities: RawCdsServiceEntity[];
  actions: RawCdsAction[];
}

/** A target like `Service.Member` addresses a member only when it is qualified. */
function matchesMember(target: string, service: string, member: string): boolean {
  return target.includes('.') && namesMatch(target, `${service}.${member}`);
}

function matchesService(target: string, service: string): boolean {
  return namesMatch(target, service);
}

export function effectiveServices(project: RawProject): EffectiveService[] {
  const annotates = resolvedAnnotates(project);
  return project.cdsFiles.flatMap((file) =>
    file.services.map((service): EffectiveService => {
      const requires = [...service.requires];
      const restrictTo = [...service.restrictTo];
      const members = [...service.entities, ...service.actions];
      for (const member of members) {
        requires.push(...member.requires);
        restrictTo.push(...member.restrictTo);
      }
      for (const annotate of annotates) {
        const applies =
          matchesService(annotate.target, service.name) ||
          members.some((member) => matchesMember(annotate.target, service.name, member.name));
        if (!applies) continue;
        requires.push(...annotate.requires);
        restrictTo.push(...annotate.restrictTo);
      }
      return {
        file: file.file,
        name: service.name,
        line: service.line,
        protocolNone: service.protocolNone,
        external: service.external,
        requires: sortedUnique(requires),
        restrictTo: sortedUnique(restrictTo),
        entities: service.entities,
        actions: service.actions,
      };
    }),
  );
}

export interface EffectiveEntity {
  file: string;
  name: string;
  line: number;
  fields: string[];
  associations: RawCdsAssociation[];
  /** Association targets with `using` aliases resolved. */
  linkTargets: string[];
  /** Declared inline, or through an annotate on the entity or on a projection of it. */
  personalData: boolean;
}

/** The db entities an annotate marks: directly, or through the service projections it targets. */
function annotatedEntities(project: RawProject, target: string): Set<string> {
  const matched = new Set<string>();
  const projections = project.cdsFiles.flatMap((file) =>
    file.services.flatMap((service) =>
      service.entities
        .filter((entity) => matchesMember(target, service.name, entity.name))
        .map((entity) => ({ file, entity })),
    ),
  );
  const dbEntities = project.cdsFiles.flatMap((file) => file.entities);
  if (projections.length > 0) {
    for (const { file, entity } of projections) {
      if (entity.projectionOf === null) continue;
      const source = resolveTarget(file, entity.projectionOf);
      for (const db of dbEntities) if (namesMatch(source, db.name)) matched.add(db.name);
    }
    return matched;
  }
  for (const db of dbEntities) if (namesMatch(target, db.name)) matched.add(db.name);
  return matched;
}

export function effectiveEntities(project: RawProject): EffectiveEntity[] {
  const marked = new Set<string>();
  for (const annotate of resolvedAnnotates(project)) {
    if (!annotate.personalData) continue;
    for (const name of annotatedEntities(project, annotate.target)) marked.add(name);
  }
  return project.cdsFiles.flatMap((file) =>
    file.entities.map((entity) => ({
      file: file.file,
      name: entity.name,
      line: entity.line,
      fields: entity.fields,
      associations: entity.associations,
      linkTargets: entity.associations.map((association) =>
        resolveTarget(file, association.target),
      ),
      personalData: entity.personalData || marked.has(entity.name),
    })),
  );
}

/** Every role named in `@requires` or `@restrict.to`, without pseudo-roles and `$`/`:` names. */
export function referencedRoles(project: RawProject): string[] {
  const roles: string[] = [];
  for (const file of project.cdsFiles) {
    for (const service of file.services) {
      roles.push(...service.requires, ...service.restrictTo);
      for (const member of [...service.entities, ...service.actions]) {
        roles.push(...member.requires, ...member.restrictTo);
      }
    }
    for (const annotate of file.annotates) roles.push(...annotate.requires, ...annotate.restrictTo);
  }
  return sortedUnique(roles.filter((role) => !PSEUDO_ROLES.includes(role) && !/[$:]/.test(role)));
}

/** `@PersonalData` appears anywhere in the model, inline or in an annotate. */
export function hasPersonalDataDeclared(project: RawProject): boolean {
  return project.cdsFiles.some(
    (file) =>
      file.entities.some((entity) => entity.personalData) ||
      file.annotates.some((annotate) => annotate.personalData),
  );
}

export interface PersonalEntity extends EffectiveEntity {
  strongFields: string[];
  weakFields: string[];
  /** The personal entity an association points to, when that is why weak fields count. */
  linkedTo: string | null;
}

function lastSegment(name: string): string {
  return name.slice(name.lastIndexOf('.') + 1);
}

/**
 * Entities that look like they hold personal data: a strong field (name,
 * contact, identifier), or weak fields (address parts) on an entity that
 * links to a personal entity or is named like one. `personalData` says
 * whether the model already declares it.
 */
export function personalEntities(project: RawProject): PersonalEntity[] {
  const entities = effectiveEntities(project);
  const isPersonal = (entity: EffectiveEntity): boolean =>
    entity.personalData || entity.fields.some(isStrongPersonalField);
  const result: PersonalEntity[] = [];
  for (const entity of entities) {
    const strongFields = entity.fields.filter(isStrongPersonalField);
    const weakFields = entity.fields.filter(
      (field) => isWeakPersonalField(field) && !isStrongPersonalField(field),
    );
    if (strongFields.length > 0) {
      result.push({ ...entity, strongFields, weakFields, linkedTo: null });
      continue;
    }
    if (weakFields.length === 0) continue;
    const linked = entity.linkTargets
      .map((target) =>
        entities.find(
          (other) => other !== entity && namesMatch(target, other.name) && isPersonal(other),
        ),
      )
      .find((other) => other !== undefined);
    if (linked) {
      result.push({ ...entity, strongFields, weakFields, linkedTo: linked.name });
    } else if (PERSONAL_ENTITY_NAME.test(lastSegment(entity.name))) {
      result.push({ ...entity, strongFields, weakFields, linkedTo: null });
    }
  }
  return result;
}
