/**
 * OS-backed device credential storage.
 *
 * The config file remains the durable home for non-secret device metadata. On
 * supported desktops the credential itself lives in the user's OS vault:
 * macOS Keychain (`security`) or Linux Secret Service (`secret-tool`). Windows
 * deliberately stays on the owner-only file fallback until the agent has a
 * direct DPAPI/Credential Manager binding — putting a secret on a PowerShell
 * command line would be worse than the existing 0600 file.
 */
import { spawnSync } from "node:child_process"
import { GatewayError } from "@cg/core"

export const CREDENTIAL_REF = "os:connectors-agent:v1"
const SERVICE = "connectors-agent"
const ACCOUNT_PREFIX = "device:"
const COMMAND_TIMEOUT_MS = 5_000

type Platform = NodeJS.Platform

type RunResult = { status: number | null; stdout: string }
type Run = (command: string, args: readonly string[], input?: string) => RunResult

export type NativeCredentialStore = {
  kind: "macos-keychain" | "linux-secret-service"
  read(deviceId: string): string | null
  write(deviceId: string, credential: string): void
  delete(deviceId: string): boolean
}

export type NativeCredentialStoreOptions = {
  platform?: Platform
  env?: Record<string, string | undefined>
  run?: Run
}

export function createNativeCredentialStore(options: NativeCredentialStoreOptions = {}): NativeCredentialStore | null {
  const platform = options.platform ?? process.platform
  const env = options.env ?? process.env
  const run = options.run ?? runCommand
  if (platform === "darwin") return macosStore(run)
  if (platform === "linux" && hasSecretServiceSession(env) && commandExists("secret-tool", run)) return linuxStore(run)
  return null
}

function macosStore(run: Run): NativeCredentialStore | null {
  if (!commandExists("security", run)) return null
  // `security add-generic-password -w <secret>` exposes the value in argv, while
  // omitting the value is interactive. Refuse that tradeoff: the existing 0600
  // file is safer until a direct Security.framework binding exists.
  return null
}

function linuxStore(run: Run): NativeCredentialStore {
  const attrs = (deviceId: string): string[] => ["service", SERVICE, "device", deviceId]
  return {
    kind: "linux-secret-service",
    read(deviceId) {
      const result = run("secret-tool", ["lookup", ...attrs(deviceId)])
      if (result.status === 1) return null
      if (result.status !== 0) throw unavailable()
      return normalizeCredential(result.stdout)
    },
    write(deviceId, credential) {
      // secret-tool reads the secret from stdin; it never appears in argv.
      const result = run("secret-tool", ["store", "--label", "Connectors Agent device credential", ...attrs(deviceId)], `${credential}\n`)
      if (result.status !== 0) throw unavailable()
    },
    delete(deviceId) {
      const result = run("secret-tool", ["clear", ...attrs(deviceId)])
      if (result.status === 1) return false
      if (result.status !== 0) throw unavailable()
      return true
    },
  }
}

function hasSecretServiceSession(env: Record<string, string | undefined>): boolean {
  return Boolean(env["DBUS_SESSION_BUS_ADDRESS"]?.trim())
}

function commandExists(command: string, run: Run): boolean {
  const result = run(command, ["--help"])
  // A spawn that never happened has no exit status. Bun reports that as `undefined`,
  // Node as `null`, so only an actual number means the binary was executed. Treating
  // `undefined` as "found" made every Linux box claim a Secret Service it does not have.
  return typeof result.status === "number"
}

function runCommand(command: string, args: readonly string[], input?: string): RunResult {
  try {
    const result = spawnSync(command, [...args], {
      encoding: "utf8",
      input,
      timeout: COMMAND_TIMEOUT_MS,
      windowsHide: true,
      stdio: [input === undefined ? "ignore" : "pipe", "pipe", "ignore"],
    })
    // Bun returns `undefined` where Node returns `null` for a signal or a failed spawn.
    // Normalize once here so callers never have to know which runtime they are on.
    return {
      status: typeof result.status === "number" ? result.status : null,
      stdout: typeof result.stdout === "string" ? result.stdout : "",
    }
  } catch {
    return { status: null, stdout: "" }
  }
}

function normalizeCredential(raw: string): string {
  const value = raw.replace(/[\r\n]+$/, "")
  if (value.length === 0 || value.length > 512 || /[\u0000-\u001f\u007f]/.test(value)) throw unavailable()
  return value
}

function account(deviceId: string): string { return `${ACCOUNT_PREFIX}${deviceId}` }
function unavailable(): GatewayError { return new GatewayError("INTERNAL", "The OS credential store is unavailable.") }
