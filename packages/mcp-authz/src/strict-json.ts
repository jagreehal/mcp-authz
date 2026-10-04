/**
 * JSON that every parser reads the same way.
 *
 * A message is authorized as one parser reads it and acted on as another reads
 * it. Parsers resolve a repeated key differently (JavaScript keeps the last,
 * others the first), so a body naming two tools can be priced as one and run
 * as the other. Refusing the ambiguity is the only safe reading.
 */

/**
 * Whether any object repeats a key, compared after unescaping, so `"name"` and
 * `"na\u006de"` are the same key. Only called on text JSON.parse accepted,
 * which is what lets it skip validating anything else.
 */
export function hasDuplicateKey(text: string): boolean {
  const scopes: (Set<string> | undefined)[] = [];
  for (let i = 0; i < text.length; i++) {
    const char = text[i];
    if (char === '{') scopes.push(new Set());
    else if (char === '[') scopes.push(undefined);
    else if (char === '}' || char === ']') scopes.pop();
    else if (char === '"') {
      let end = i + 1;
      while (text[end] !== '"') end += text[end] === '\\' ? 2 : 1;
      let next = end + 1;
      while (text[next] === ' ' || text[next] === '\t' || text[next] === '\r' || text[next] === '\n') next++;
      const scope = scopes.at(-1);
      // In an object, a string followed by a colon is a key.
      if (scope && text[next] === ':') {
        const key = JSON.parse(text.slice(i, end + 1)) as string;
        if (scope.has(key)) return true;
        scope.add(key);
      }
      i = end;
    }
  }
  return false;
}

/**
 * JSON numbers, read without rounding.
 *
 * `JSON.parse` turns every number into the nearest double. A value checked
 * that way can differ from the one a server reading it exactly (a Python int,
 * a Decimal, a Go big number) acts on: `9007199254740993`, `9007199254740993e0`
 * and `1.0000000000000001` all check as their rounded neighbour. And an answer
 * re-serialized from a double arrives changed. Both are fixed with
 * `JSON.rawJSON`, which `JSON.stringify` writes out as the text it was given.
 * Node 24 and current Workers have it.
 */
const exactJson = JSON as unknown as {
  rawJSON(text: string): object;
  isRawJSON(value: unknown): boolean;
};
type Context = { source?: string };

/**
 * For checking: a number whose text means exactly the double it parses to
 * stays a number, so `1.0`, `0.1` and `1e3` check as written. Any other comes
 * back as a raw value, which `holdsInexactNumber` finds and a check refuses,
 * rather than approve the rounded neighbour of what the server will run.
 */
export function parseChecked(text: string): unknown {
  return JSON.parse(text, (_key, value: unknown, context?: Context) =>
    typeof value === 'number' && context?.source !== undefined && !sameDecimal(context.source, String(value))
      ? exactJson.rawJSON(context.source)
      : value,
  );
}

/** For rewriting: every number keeps the text it arrived as, digit for digit. */
export function parseVerbatim(text: string): unknown {
  return JSON.parse(text, (_key, value: unknown, context?: Context) =>
    typeof value === 'number' && context?.source !== undefined ? exactJson.rawJSON(context.source) : value,
  );
}

/** Whether a value parsed by `parseChecked` holds a number that cannot be checked exactly. */
export function holdsInexactNumber(value: unknown): boolean {
  if (exactJson.isRawJSON(value)) return true;
  if (typeof value !== 'object' || value === null) return false;
  return Object.values(value).some(holdsInexactNumber);
}

/**
 * Whether two JSON number texts denote the same decimal value, compared as
 * digits and an exponent so that no double is involved: `1.0` and `1`, `1e3`
 * and `1000` are the same; `9007199254740993e0` and `9007199254740992` are not.
 */
function sameDecimal(a: string, b: string): boolean {
  const x = decimal(a);
  const y = decimal(b);
  return (
    x !== undefined &&
    y !== undefined &&
    x.sign === y.sign &&
    x.digits === y.digits &&
    x.exponent === y.exponent
  );
}

function decimal(text: string): { sign: string; digits: string; exponent: number } | undefined {
  const match = /^(-?)(\d+)(?:\.(\d+))?(?:[eE]([+-]?\d+))?$/.exec(text);
  if (!match) return undefined;
  const [, sign = '', whole = '', fraction = '', power = '0'] = match;
  let digits = (whole + fraction).replace(/^0+/, '');
  let exponent = Number(power) - fraction.length;
  if (digits === '') return { sign: '', digits: '0', exponent: 0 };
  const trailing = /0+$/.exec(digits)?.[0].length ?? 0;
  digits = digits.slice(0, digits.length - trailing);
  exponent += trailing;
  return { sign, digits, exponent };
}
