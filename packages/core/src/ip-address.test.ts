import { describe, expect, test } from "bun:test"
import { blockedRange, isLoopback } from "./ip-address"

describe("blockedRange", () => {
  const blocked = [
    "0.1.2.3", "10.0.0.1", "100.64.0.1", "100.127.255.254", "127.0.0.1",
    "169.254.169.254", "172.16.0.1", "172.31.255.255", "192.0.0.8", "192.0.2.1",
    "192.88.99.1", "192.168.1.1", "198.18.0.1", "198.19.255.254", "198.51.100.1",
    "203.0.113.1", "224.0.0.1", "239.255.255.255", "240.0.0.1", "255.255.255.255",
    "[::]", "[::1]", "[100::1]", "[2001:db8::1]", "[fc00::1]", "[fd00::1]",
    "[fe80::1]", "[ff02::1]", "[::ffff:10.0.0.1]", "[::ffff:169.254.169.254]",
  ]
  for (const host of blocked) {
    test(`blocks ${host}`, () => expect(blockedRange(host)).not.toBeNull())
  }

  const publicHosts = ["8.8.8.8", "1.1.1.1", "11.0.0.1", "100.128.0.1", "172.32.0.1", "192.167.0.1", "2001:4860:4860::8888", "example.com"]
  for (const host of publicHosts) {
    test(`does not classify ${host} as blocked`, () => expect(blockedRange(host)).toBeNull())
  }
})

describe("isLoopback", () => {
  for (const host of ["localhost", "api.localhost", "LOCALHOST.", "127.9.8.7", "[::1]", "[::ffff:127.0.0.1]"]) {
    test(`recognizes ${host}`, () => expect(isLoopback(host)).toBe(true))
  }
  test("does not trust a lookalike suffix", () => expect(isLoopback("localhost.evil.test")).toBe(false))
})

describe("IPv6 public reachability at the SSRF boundary", () => {
  for (const host of [
    "fec0::1", "feff:ffff::1", "64:ff9b:1::1", "100:0:0:1::1",
    "2001:2::1", "2001:1::4", "2001:10::1", "2001:100::1",
    "2001:0:1:2:3:4:5:6", "2002:a00:1::1", "2002:808:808::1",
    "3fff::1", "3fff:fff:ffff::1", "5f00::1", "4000::1", "1234::1",
    "::808:808", "64:ff9b::a9fe:a9fe", "64:ff9b::127.0.0.1",
    "64:ff9b::10.0.0.1", "64:ff9b::c0a8:1", "64:ff9b::192.0.2.1",
  ]) {
    test(`rejects non-global or translated-private ${host}`, () => {
      expect(blockedRange(host)).not.toBeNull()
      expect(blockedRange("[" + host + "]")).not.toBeNull()
    })
  }
  for (const host of [
    "2001:4860:4860::8888", "2606:4700:4700::1111",
    "::ffff:8.8.8.8", "64:ff9b::8.8.8.8", "64:ff9b::101:101",
    "2001:1::1", "2001:1::2", "2001:1::3", "2001:3::1",
    "2001:4:112::1", "2001:20::1", "2001:30::1", "3fff:1000::1",
  ]) {
    test(`preserves public address ${host}`, () => expect(blockedRange(host)).toBeNull())
  }
})

describe("IPv6 blocked-prefix boundaries", () => {
  for (const host of [
    "64:ff9b:1::", "64:ff9b:1:ffff:ffff:ffff:ffff:ffff",
    "100:0:0:1::", "100:0:0:1:ffff:ffff:ffff:ffff",
    "2001:2::", "2001:2:0:ffff:ffff:ffff:ffff:ffff",
    "2001:1ff:ffff:ffff:ffff:ffff:ffff:ffff", "2001:2:1::",
    "3fff::", "3fff:fff:ffff:ffff:ffff:ffff:ffff:ffff",
    "fec0::", "feff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
    "64:ff9b::a00:0", "64:ff9b::aff:ffff",
  ]) {
    test(`rejects prefix boundary ${host}`, () => expect(blockedRange(host)).not.toBeNull())
  }
  for (const host of [
    "2001:200::", "3ffe:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "3fff:1000::",
    "64:ff9b::9ff:ffff", "64:ff9b::b00:0", "::ffff:9ff:ffff", "::ffff:b00:0",
  ]) {
    test(`preserves adjacent public address ${host}`, () => expect(blockedRange(host)).toBeNull())
  }
})
