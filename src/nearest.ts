/**
 * Nearest-candidate lookup for did-you-mean suggestions. A tiny
 * Levenshtein implementation is all that is needed: the candidate sets
 * (directive names, keyword names) are a few dozen strings.
 */

/** Classic dynamic-programming edit distance. */
export function editDistance(a: string, b: string): number {
  if (a === b) return 0;
  const rows = a.length + 1;
  const cols = b.length + 1;
  let previous: number[] = Array.from({ length: cols }, (_, j) => j);
  for (let i = 1; i < rows; i += 1) {
    const current: number[] = [i];
    for (let j = 1; j < cols; j += 1) {
      const substitution = (previous[j - 1] ?? 0) + (a[i - 1] === b[j - 1] ? 0 : 1);
      const insertion = (current[j - 1] ?? 0) + 1;
      const deletion = (previous[j] ?? 0) + 1;
      current.push(Math.min(substitution, insertion, deletion));
    }
    previous = current;
  }
  return previous[cols - 1] ?? 0;
}

/**
 * The closest candidate within a length-scaled edit-distance budget, or
 * null when nothing is plausibly "what they meant". Ties resolve to the
 * first candidate in iteration order, which keeps output deterministic.
 */
export function nearest(word: string, candidates: Iterable<string>): string | null {
  const needle = word.toLowerCase();
  const budget = needle.length <= 4 ? 1 : needle.length <= 8 ? 2 : 3;
  let best: string | null = null;
  let bestDistance = budget + 1;
  for (const candidate of candidates) {
    const distance = editDistance(needle, candidate.toLowerCase());
    if (distance > 0 && distance < bestDistance) {
      best = candidate;
      bestDistance = distance;
    }
  }
  return best;
}
