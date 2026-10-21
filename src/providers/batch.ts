import { AuthError, ProviderError, UpdateError } from "./types";

/**
 * Runs `update` for each target in turn, continuing past failures so that one
 * broken target doesn't block the rest, then reports every failure at once.
 *
 * - An {@link AuthError} aborts immediately: every target shares the token, so
 *   the remaining calls would fail the same way.
 * - A single target's error is rethrown as-is.
 * - Multiple failures are summarized in one error: an {@link UpdateError} when
 *   every failure was one (the caller's fault), otherwise a
 *   {@link ProviderError}.
 */
export async function updateEach<T>(
  targets: T[],
  describe: (target: T) => string,
  update: (target: T) => Promise<void>
): Promise<void> {
  const failures: { target: T; err: unknown }[] = [];

  for (const target of targets) {
    try {
      await update(target);
    } catch (err) {
      if (err instanceof AuthError) {
        throw err;
      }
      console.error(`Failed to update ${describe(target)}:`, err);
      failures.push({ target, err });
    }
  }

  if (failures.length === 0) {
    return;
  }
  if (targets.length === 1) {
    throw failures[0].err;
  }

  const details = failures
    .map(({ target, err }) => `${describe(target)}: ${err instanceof Error ? err.message : String(err)}`)
    .join("; ");
  const message = `${failures.length} of ${targets.length} update(s) failed: ${details}`;
  if (failures.every(({ err }) => err instanceof UpdateError)) {
    throw new UpdateError(message);
  }
  throw new ProviderError(message);
}
