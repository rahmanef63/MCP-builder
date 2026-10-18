/**
 * The one Ajv instance for the whole process.
 *
 * A second instance would mean a second meta-schema registry and duplicated
 * compilation work; a per-call instance would recompile every action schema on
 * every request. Compiled validators are cached by schema *identity* (WeakMap),
 * so a manifest object that is loaded once is compiled once.
 */
import Ajv from "ajv/dist/2020"
import type { ErrorObject, ValidateFunction } from "ajv/dist/2020"
import { GatewayError } from "@cg/core"
import type { JsonSchema } from "@cg/core"
import { safeErrorMessage } from "./format-errors"

const ajv = new Ajv({
  // Manifests carry annotation keywords Ajv does not know (title/description on
  // arbitrary subschemas). Unknown keywords must not hard-fail the gateway.
  strict: false,
  // The caller gets one aggregated message instead of one error per round trip.
  allErrors: true,
})

const compiled = new WeakMap<object, ValidateFunction>()

/**
 * Compile the schema WITHOUT its root `$id`.
 *
 * `$id` is caller data: once manifests come from the database, one owner could
 * declare the `$id` of another owner's schema. Ajv keys its global registry on
 * `$id`, so registering it would either substitute the other schema's validator
 * or make the second registration throw. Neither may depend on a name a caller
 * chose, so no caller `$id` is ever registered. Internal `#/$defs/...` and
 * `#anchor` references resolve relative to the document, not to `$id`, and are
 * unaffected; the caller's object is never mutated.
 */
function withoutRootId(schema: JsonSchema): JsonSchema {
  if (!("$id" in schema)) return schema
  const { $id: _unregistered, ...rest } = schema
  return rest
}

/**
 * Compile (or reuse) a validator for `schema`.
 * Cache hits are decided by schema IDENTITY (WeakMap) alone — never by `$id`,
 * so two schemas that share an `$id` still validate independently.
 * Throws INVALID_INPUT if the schema itself is not a valid JSON Schema —
 * the reason is deliberately not echoed, since a schema may be attacker-shaped.
 */
export function compileSchema(schema: JsonSchema): ValidateFunction {
  const cachedValidator = compiled.get(schema)
  if (cachedValidator) return cachedValidator

  let validate: ValidateFunction
  try {
    validate = ajv.compile(withoutRootId(schema))
  } catch {
    throw new GatewayError("INVALID_INPUT", "Schema is not a valid JSON Schema document.")
  }

  // A Promise is truthy before validation finishes; callers require a boolean.
  if ("$async" in validate && validate.$async === true) {
    throw new GatewayError("INVALID_INPUT", "Schema must use synchronous validation.")
  }

  compiled.set(schema, validate)
  return validate
}

/**
 * Validate `value` against `schema`, throwing INVALID_INPUT with an aggregated,
 * value-free message. `label` prefixes the message, e.g. "Invalid job envelope".
 */
export function validateOrThrow(schema: JsonSchema, value: unknown, label: string): void {
  const validate = compileSchema(schema)
  if (validate(value)) return

  const errors: readonly ErrorObject[] | null | undefined = validate.errors
  throw new GatewayError("INVALID_INPUT", safeErrorMessage(label, errors))
}
