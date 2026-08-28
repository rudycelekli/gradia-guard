const FORBIDDEN_KEY =
  /(?:^|[_-])(api[_-]?key|authorization|bearer|cookie|credential|password|private[_-]?key|secret|session[_-]?token|token)(?:$|[_-])/i;
const PRIVATE_REASONING_KEY =
  /(?:^|[_-])(chain[_-]?of[_-]?thought|hidden[_-]?reasoning|private[_-]?reasoning|reasoning|scratchpad|thoughts?)(?:$|[_-])/i;
const SECRET_FLAG =
  /^(?:--?)?(?:api[_-]?key|authorization|bearer|cookie|credential|password|private[_-]?key|secret|session[_-]?token|token)(?:=|$)/i;

export class UnsafeEvidenceError extends Error {
  readonly code: string;

  constructor(code: string) {
    super(code);
    this.name = "UnsafeEvidenceError";
    this.code = code;
  }
}

export function assertEvidenceSafe(value: unknown, path = "$", seen = new Set<object>()): void {
  if (value === null || ["boolean", "number", "string"].includes(typeof value)) return;
  if (typeof value !== "object") throw new UnsafeEvidenceError(`evidence_unsupported_type:${path}`);
  if (seen.has(value)) throw new UnsafeEvidenceError(`evidence_cycle:${path}`);
  seen.add(value);
  if (Array.isArray(value)) {
    value.forEach((item, index) => assertEvidenceSafe(item, `${path}[${index}]`, seen));
  } else {
    for (const [key, item] of Object.entries(value)) {
      if (FORBIDDEN_KEY.test(key)) throw new UnsafeEvidenceError(`evidence_secret_shape_refused:${path}.${key}`);
      if (PRIVATE_REASONING_KEY.test(key)) {
        throw new UnsafeEvidenceError(`evidence_private_reasoning_refused:${path}.${key}`);
      }
      assertEvidenceSafe(item, `${path}.${key}`, seen);
    }
  }
  seen.delete(value);
}

export function assertCommandSafe(argv: readonly string[]): void {
  for (const [index, arg] of argv.entries()) {
    if (SECRET_FLAG.test(arg)) throw new UnsafeEvidenceError(`command_secret_flag_refused:${index}`);
    const assignment = /^([A-Za-z_][A-Za-z0-9_]*)=/.exec(arg);
    if (assignment?.[1] && FORBIDDEN_KEY.test(assignment[1])) {
      throw new UnsafeEvidenceError(`command_secret_assignment_refused:${index}`);
    }
    if (/^(?:authorization|cookie):/i.test(arg)) {
      throw new UnsafeEvidenceError(`command_secret_header_refused:${index}`);
    }
  }
}

export function assertStableId(value: string, field: string): void {
  if (!/^[A-Za-z0-9][A-Za-z0-9_.:-]{0,199}$/.test(value)) {
    throw new UnsafeEvidenceError(`${field}_invalid`);
  }
}

export function assertEnvironmentName(value: string): void {
  if (!/^[A-Z][A-Z0-9_]{0,99}$/.test(value)) {
    throw new UnsafeEvidenceError("environment_name_invalid");
  }
}
