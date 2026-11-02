import { type EaseOfAttack, type Impact, criticality } from '../../model/criticality.js';
import type { Finding, FindingLocation } from '../../model/finding.js';
import type { RawProject } from '../../model/raw.js';
import type { Severity } from '../../model/severity.js';
import type { AnalyzerContext } from '../types.js';

/** Severity from the criticality matrix; both inputs are recorded in the evidence. */
export interface MatrixSeverity {
  impact: Impact;
  easeOfAttack: EaseOfAttack;
}

export interface ProjectFindingSpec {
  id: string;
  title: string;
  /** What the finding is about: the service, entity, role, scope, route source, file or column. */
  subject: string;
  /** A fixed severity, or the matrix inputs that decide it. */
  severity: Severity | MatrixSeverity;
  /** Facts beyond the subject: identifiers, counts and booleans only. */
  evidence?: Record<string, unknown>;
  location?: FindingLocation;
  remediation: string;
  references: string[];
}

function isMatrix(severity: Severity | MatrixSeverity): severity is MatrixSeverity {
  return typeof severity === 'object';
}

/**
 * Builds a finding about a local project. Every project finding goes through
 * here so that `evidence.subject` is always set (the SARIF fingerprint and
 * the sort order depend on it) and the matrix inputs are kept as evidence.
 */
export function projectFinding(
  context: AnalyzerContext,
  project: RawProject,
  spec: ProjectFindingSpec,
): Finding {
  const matrix = isMatrix(spec.severity) ? spec.severity : undefined;
  const severity = isMatrix(spec.severity)
    ? criticality(spec.severity.impact, spec.severity.easeOfAttack)
    : spec.severity;
  return {
    id: spec.id,
    severity,
    title: spec.title,
    app: context.projectRef(project),
    evidence: {
      subject: spec.subject,
      ...spec.evidence,
      ...(matrix ? { impact: matrix.impact, easeOfAttack: matrix.easeOfAttack } : {}),
    },
    remediation: spec.remediation,
    references: spec.references,
    ...(spec.location ? { location: spec.location } : {}),
  };
}
