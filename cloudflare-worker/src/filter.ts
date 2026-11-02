/**
 * Strict Meta-only filter, mirrored on Android (MetaFilter.java).
 * Both conditions must hold: exact allowlisted sender AND exact template body.
 * Empty allowlist forwards nothing. No partial, wildcard or fuzzy matching.
 */

export const META_CODE_REGEX =
  /^\s*([0-9]{6})\s+is your Meta confirmation code\.?\s*$/i;

export function normaliseSender(sender: string): string {
  return sender.trim().toLowerCase();
}

export function parseAllowlist(raw: string | undefined | null): Set<string> {
  const out = new Set<string>();
  if (!raw) return out;
  for (const part of raw.split(",")) {
    const trimmed = part.trim();
    if (trimmed && trimmed !== "*") out.add(normaliseSender(trimmed));
  }
  return out;
}

export function isSenderAllowlisted(
  allowlist: Set<string>,
  sender: string,
): boolean {
  if (allowlist.size === 0 || !sender) return false;
  const wanted = normaliseSender(sender);
  return wanted !== "" && allowlist.has(wanted);
}

export function extractCode(body: string): string | null {
  if (typeof body !== "string") return null;
  const m = META_CODE_REGEX.exec(body);
  return m ? m[1] : null;
}

export function accepts(
  allowlist: Set<string>,
  sender: string,
  body: string,
): boolean {
  return isSenderAllowlisted(allowlist, sender) && extractCode(body) !== null;
}
