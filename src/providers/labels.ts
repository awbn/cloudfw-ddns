import { UpdateError } from "./types";

// A comma-separated list of `key` or `key=value` terms, all of which must match.
const SELECTOR_PATTERN = /^[a-zA-Z0-9_.\/\-]+(=[a-zA-Z0-9_.\/\-]+)?(,[a-zA-Z0-9_.\/\-]+(=[a-zA-Z0-9_.\/\-]+)?)*$/;

/**
 * Parses a `label:<selector>` or `l:<selector>` hostname into its selector
 * (e.g. `env=prod,role=bastion`). Returns `null` when the input carries no
 * label prefix, and throws an {@link UpdateError} for a malformed selector.
 */
export function parseLabelSelector(input: string): string | null {
  let selector: string | null = null;
  if (input.startsWith("label:")) {
    selector = input.slice(6);
  } else if (input.startsWith("l:")) {
    selector = input.slice(2);
  }
  if (selector !== null && !SELECTOR_PATTERN.test(selector)) {
    throw new UpdateError("Invalid label selector format");
  }
  return selector;
}
