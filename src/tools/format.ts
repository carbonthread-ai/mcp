const MAX_STRING = 8_000;
const MAX_ARRAY = 60;
const MAX_TOTAL = 120_000;

/** Keeps tool results inside what an AI can read in one go: long text and long lists are cut, with a note. */
export function compact(value: unknown, depth = 0): unknown {
  if (typeof value === "string") {
    return value.length > MAX_STRING ? `${value.slice(0, MAX_STRING)}… [${value.length - MAX_STRING} more characters]` : value;
  }
  if (Array.isArray(value)) {
    const items = value.slice(0, MAX_ARRAY).map((v) => compact(v, depth + 1));
    if (value.length > MAX_ARRAY) items.push(`… ${value.length - MAX_ARRAY} more items not shown; narrow the request`);
    return items;
  }
  if (value && typeof value === "object") {
    if (depth > 8) return "[nested too deep]";
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value)) {
      if (v === null || v === undefined) continue;
      out[k] = compact(v, depth + 1);
    }
    return out;
  }
  return value;
}

export function toText(value: unknown): string {
  const text = typeof value === "string" ? value : JSON.stringify(compact(value), null, 2);
  return text.length > MAX_TOTAL ? `${text.slice(0, MAX_TOTAL)}\n… [cut: the result was too long; narrow the request]` : text;
}

/** Picks the fields worth showing from each row of a list, so a list stays readable. */
export function pickEach<T extends Record<string, unknown>>(rows: T[] | undefined, keys: string[]): Record<string, unknown>[] {
  return (rows ?? []).map((row) => Object.fromEntries(keys.filter((k) => row[k] !== undefined && row[k] !== null).map((k) => [k, row[k]])));
}
