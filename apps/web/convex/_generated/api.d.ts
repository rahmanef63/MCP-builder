/* eslint-disable */
/**
 * Generated `api` utility.
 *
 * THIS CODE IS AUTOMATICALLY GENERATED.
 *
 * To regenerate, run `npx convex dev`.
 * @module
 */

import type * as _shared_api_key_record from "../_shared/api_key_record.js";
import type * as _shared_audit_record from "../_shared/audit_record.js";
import type * as _shared_auth from "../_shared/auth.js";
import type * as _shared_code_hash from "../_shared/code_hash.js";
import type * as _shared_connection_record from "../_shared/connection_record.js";
import type * as _shared_constant_time from "../_shared/constant_time.js";
import type * as _shared_device_record from "../_shared/device_record.js";
import type * as _shared_errors from "../_shared/errors.js";
import type * as _shared_input from "../_shared/input.js";
import type * as _shared_ip_literal from "../_shared/ip_literal.js";
import type * as _shared_limits from "../_shared/limits.js";
import type * as _shared_lookup from "../_shared/lookup.js";
import type * as _shared_pairing_record from "../_shared/pairing_record.js";
import type * as _shared_policy_record from "../_shared/policy_record.js";
import type * as _shared_redirect_uri from "../_shared/redirect_uri.js";
import type * as _shared_sealed_envelope from "../_shared/sealed_envelope.js";
import type * as _shared_upstream_url from "../_shared/upstream_url.js";
import type * as _shared_validators from "../_shared/validators.js";
import type * as auth from "../auth.js";
import type * as crons from "../crons.js";
import type * as features_api_keys_limits from "../features/api_keys/limits.js";
import type * as features_api_keys_mutations from "../features/api_keys/mutations.js";
import type * as features_api_keys_queries from "../features/api_keys/queries.js";
import type * as features_approvals_mutations from "../features/approvals/mutations.js";
import type * as features_approvals_queries from "../features/approvals/queries.js";
import type * as features_audit_queries from "../features/audit/queries.js";
import type * as features_auth_identity from "../features/auth/identity.js";
import type * as features_auth_queries from "../features/auth/queries.js";
import type * as features_connections_mutations from "../features/connections/mutations.js";
import type * as features_connections_queries from "../features/connections/queries.js";
import type * as features_devices_mutations from "../features/devices/mutations.js";
import type * as features_devices_queries from "../features/devices/queries.js";
import type * as features_oauth_mutations from "../features/oauth/mutations.js";
import type * as features_oauth_queries from "../features/oauth/queries.js";
import type * as features_pairing_mutations from "../features/pairing/mutations.js";
import type * as features_pairing_queries from "../features/pairing/queries.js";
import type * as features_policy_mutations from "../features/policy/mutations.js";
import type * as features_policy_queries from "../features/policy/queries.js";
import type * as google_provider from "../google_provider.js";
import type * as http from "../http.js";
import type * as maintenance_oauth_sweep from "../maintenance/oauth_sweep.js";
import type * as service_apiKeys from "../service/apiKeys.js";
import type * as service_approvals from "../service/approvals.js";
import type * as service_audit from "../service/audit.js";
import type * as service_connections from "../service/connections.js";
import type * as service_devices from "../service/devices.js";
import type * as service_gateway_lease from "../service/gateway_lease.js";
import type * as service_oauth from "../service/oauth.js";
import type * as service_pairing from "../service/pairing.js";
import type * as service_policy from "../service/policy.js";
import type * as service_rate_limits from "../service/rate_limits.js";
import type * as service_relay_routes from "../service/relay_routes.js";

import type {
  ApiFromModules,
  FilterApi,
  FunctionReference,
} from "convex/server";

declare const fullApi: ApiFromModules<{
  "_shared/api_key_record": typeof _shared_api_key_record;
  "_shared/audit_record": typeof _shared_audit_record;
  "_shared/auth": typeof _shared_auth;
  "_shared/code_hash": typeof _shared_code_hash;
  "_shared/connection_record": typeof _shared_connection_record;
  "_shared/constant_time": typeof _shared_constant_time;
  "_shared/device_record": typeof _shared_device_record;
  "_shared/errors": typeof _shared_errors;
  "_shared/input": typeof _shared_input;
  "_shared/ip_literal": typeof _shared_ip_literal;
  "_shared/limits": typeof _shared_limits;
  "_shared/lookup": typeof _shared_lookup;
  "_shared/pairing_record": typeof _shared_pairing_record;
  "_shared/policy_record": typeof _shared_policy_record;
  "_shared/redirect_uri": typeof _shared_redirect_uri;
  "_shared/sealed_envelope": typeof _shared_sealed_envelope;
  "_shared/upstream_url": typeof _shared_upstream_url;
  "_shared/validators": typeof _shared_validators;
  auth: typeof auth;
  crons: typeof crons;
  "features/api_keys/limits": typeof features_api_keys_limits;
  "features/api_keys/mutations": typeof features_api_keys_mutations;
  "features/api_keys/queries": typeof features_api_keys_queries;
  "features/approvals/mutations": typeof features_approvals_mutations;
  "features/approvals/queries": typeof features_approvals_queries;
  "features/audit/queries": typeof features_audit_queries;
  "features/auth/identity": typeof features_auth_identity;
  "features/auth/queries": typeof features_auth_queries;
  "features/connections/mutations": typeof features_connections_mutations;
  "features/connections/queries": typeof features_connections_queries;
  "features/devices/mutations": typeof features_devices_mutations;
  "features/devices/queries": typeof features_devices_queries;
  "features/oauth/mutations": typeof features_oauth_mutations;
  "features/oauth/queries": typeof features_oauth_queries;
  "features/pairing/mutations": typeof features_pairing_mutations;
  "features/pairing/queries": typeof features_pairing_queries;
  "features/policy/mutations": typeof features_policy_mutations;
  "features/policy/queries": typeof features_policy_queries;
  google_provider: typeof google_provider;
  http: typeof http;
  "maintenance/oauth_sweep": typeof maintenance_oauth_sweep;
  "service/apiKeys": typeof service_apiKeys;
  "service/approvals": typeof service_approvals;
  "service/audit": typeof service_audit;
  "service/connections": typeof service_connections;
  "service/devices": typeof service_devices;
  "service/gateway_lease": typeof service_gateway_lease;
  "service/oauth": typeof service_oauth;
  "service/pairing": typeof service_pairing;
  "service/policy": typeof service_policy;
  "service/rate_limits": typeof service_rate_limits;
  "service/relay_routes": typeof service_relay_routes;
}>;

/**
 * A utility for referencing Convex functions in your app's public API.
 *
 * Usage:
 * ```js
 * const myFunctionReference = api.myModule.myFunction;
 * ```
 */
export declare const api: FilterApi<
  typeof fullApi,
  FunctionReference<any, "public">
>;

/**
 * A utility for referencing Convex functions in your app's internal API.
 *
 * Usage:
 * ```js
 * const myFunctionReference = internal.myModule.myFunction;
 * ```
 */
export declare const internal: FilterApi<
  typeof fullApi,
  FunctionReference<any, "internal">
>;

export declare const components: {};
