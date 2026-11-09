# Module 08: Deep API Security, Transport-Pinned SSRF Defense, CIDR Proxy Trust, KMS Secrets & Data Governance

This module remediates the Node.js `fetch()` / Undici vs. `https.Agent` DNS-pinning mismatch, provides a complete **DNS-rebinding-proof HTTPS requester and Undici connect-lookup pin** with redirect re-validation, response-size cutoffs, and header stripping, replaces blind proxy-hop counting with **CIDR-verified `X-Forwarded-For` traversal**, and covers KMS/Vault envelope encryption and HMAC hash-chained audit logs.

---

## 1. Threat Model, Trust Boundaries & Technical Reality of Node.js `fetch()`

| Control | Technical Vulnerability / Reality | Enforcement Location | Failure Behavior |
| :--- | :--- | :--- | :--- |
| **SSRF & DNS Rebinding (`executePinnedSafeHttpsRequest` / `createPinnedUndiciConnectLookup`)** | **Critical Node.js Reality**: Node's built-in `globalThis.fetch()` uses **Undici**, which **completely ignores `https.Agent`**! Passing an `https.Agent` to `fetch()` does not pin DNS and leaves `fetch()` vulnerable to `TTL=0` DNS rebinding. Furthermore, mixed public/private DNS responses or unvalidated `301`/`302` redirects bypass single-hop checks. | Outbound HTTP client transport layer (`https.request` with `agent` OR Undici `Agent({ connect: { lookup } })`). | Resolves all A/AAAA records once, rejects if **any** record is non-global/private, pins socket connection to the validated IP, strips sensitive headers on cross-origin redirects, re-validates every redirect hop (`maxRedirects = 3`), and aborts if response exceeds `maxResponseBytes`. |
| **Client IP Extraction (`extractTrustedClientIpByCidr`)** | Counting a fixed `trustedProxyHopCount` blindly trusts `X-Forwarded-For` even when an attacker connects directly to the server or when CDN/WAF hop counts vary. | HTTP ingress boundary starting from `socket.remoteAddress`. | Only inspects `X-Forwarded-For` if `socketRemoteAddress` is inside `trustedProxyCidrs`; walks right-to-left until the first non-trusted IP; fails closed to `socketRemoteAddress` on malformed entries. |

---

## 2. Remediated SSRF & DNS-Rebinding Defense (IPv4/IPv6 Classification, Pinned Transport & Redirect Re-Validation)

```typescript
import dns from 'node:dns/promises';
import https from 'node:https';
import net from 'node:net';

function isReservedIpv4Octets(a: number, b: number, c: number, d: number): boolean {
  if (a === 0 || a === 10 || a === 127) return true;                     // 0.0.0.0/8, 10.0.0.0/8, 127.0.0.0/8
  if (a === 169 && b === 254) return true;                               // 169.254.0.0/16 (Cloud IMDS / Link-local)
  if (a === 172 && b >= 16 && b <= 31) return true;                      // 172.16.0.0/12
  if (a === 192 && b === 168) return true;                               // 192.168.0.0/16
  if (a === 100 && b >= 64 && b <= 127) return true;                     // 100.64.0.0/10 (CGNAT)
  if (a === 192 && b === 0 && (c === 0 || c === 2)) return true;         // 192.0.0.0/24, 192.0.2.0/24
  if (a === 198 && (b === 18 || b === 19)) return true;                  // 198.18.0.0/15 (Benchmarking)
  if (a === 198 && b === 51 && c === 100) return true;                   // 198.51.100.0/24
  if (a === 203 && b === 0 && c === 113) return true;                    // 203.0.113.0/24
  if (a >= 224) return true;                                             // Multicast (224/4), Reserved (240/4) & Broadcast (255.255.255.255)
  if (a === 255 && b === 255 && c === 255 && d === 255) return true;
  return false;
}

export function parseIpv6Hextets(ip: string): number[] | null {
  // Reject IPv6 zone indices (e.g. fe80::1%eth0)
  if (ip.includes('%')) return null;
  let normalized = ip.toLowerCase();
  if (normalized.includes('.')) {
    const lastColon = normalized.lastIndexOf(':');
    const v4Part = normalized.slice(lastColon + 1);
    if (net.isIP(v4Part) !== 4) return null;
    const [o0, o1, o2, o3] = v4Part.split('.').map(Number);
    const hHigh = ((o0 << 8) | o1).toString(16);
    const hLow = ((o2 << 8) | o3).toString(16);
    normalized = `${normalized.slice(0, lastColon)}:${hHigh}:${hLow}`;
  }
  const halves = normalized.split('::');
  if (halves.length > 2) return null;
  const left = halves[0] ? halves[0].split(':') : [];
  const right = halves.length === 2 && halves[1] ? halves[1].split(':') : [];
  const missing = 8 - (left.length + right.length);
  if (missing < 0) return null;
  const full = [...left, ...Array(missing).fill('0'), ...right];
  if (full.length !== 8) return null;
  return full.map((h) => parseInt(h, 16));
}

/**
 * Classifies IPv4 and IPv6 addresses, rejecting loopback, private (RFC 1918 / ULA),
 * link-local (IMDS 169.254.169.254 / fe80::/10), multicast, unspecified, CGNAT,
 * IPv4-mapped/compatible IPv6, NAT64, 6to4, Teredo, ISATAP, Discard (100::/64), and non-global ranges.
 */
export function isPrivateOrReservedIp(ip: string): boolean {
  const cleaned = ip.trim();
  const version = net.isIP(cleaned);
  if (version === 4) {
    const [a, b, c, d] = cleaned.split('.').map(Number);
    return isReservedIpv4Octets(a, b, c, d);
  }
  if (version === 6) {
    const h = parseIpv6Hextets(cleaned);
    if (!h) return true;

    const isAllZeroPrefix = h[0] === 0 && h[1] === 0 && h[2] === 0 && h[3] === 0 && h[4] === 0;
    // :: (Unspecified) or ::1 (Loopback)
    if (isAllZeroPrefix && h[5] === 0 && h[6] === 0 && (h[7] === 0 || h[7] === 1)) return true;

    // IPv4-mapped (::ffff:0:0/96) or IPv4-compatible (::0:0/96)
    if (isAllZeroPrefix && (h[5] === 0xffff || h[5] === 0)) {
      return isReservedIpv4Octets(h[6] >> 8, h[6] & 0xff, h[7] >> 8, h[7] & 0xff);
    }

    // IPv4-translated (::ffff:0:w.x.y.z /96)
    if (h[0] === 0 && h[1] === 0 && h[2] === 0 && h[3] === 0 && h[4] === 0xffff && h[5] === 0) {
      return isReservedIpv4Octets(h[6] >> 8, h[6] & 0xff, h[7] >> 8, h[7] & 0xff);
    }

    // Discard-Only Address Block (100::/64)
    if (h[0] === 0x0100 && h[1] === 0 && h[2] === 0 && h[3] === 0) return true;

    // NAT64 Well-Known (64:ff9b::/96) & Local-Use (64:ff9b:1::/48)
    if (h[0] === 0x0064 && h[1] === 0xff9b) {
      return isReservedIpv4Octets(h[6] >> 8, h[6] & 0xff, h[7] >> 8, h[7] & 0xff);
    }

    // 6to4 (2002::/16)
    if (h[0] === 0x2002) {
      return isReservedIpv4Octets(h[1] >> 8, h[1] & 0xff, h[2] >> 8, h[2] & 0xff);
    }

    // Teredo (2001:0000::/32)
    if (h[0] === 0x2001 && h[1] === 0x0000) return true;

    // Benchmarking (2001:0002::/48), Orchid (2001:0010::/28), Documentation (2001:0db8::/32)
    if (h[0] === 0x2001 && (h[1] === 0x0002 || (h[1] & 0xfff0) === 0x0010 || h[1] === 0x0db8)) {
      return true;
    }

    // ISATAP (::0000:5efe:w.x.y.z or ::0200:5efe:w.x.y.z)
    if ((h[4] === 0x0000 || h[4] === 0x0200) && h[5] === 0x5efe) {
      return isReservedIpv4Octets(h[6] >> 8, h[6] & 0xff, h[7] >> 8, h[7] & 0xff);
    }

    if ((h[0] & 0xffc0) === 0xfe80) return true; // Link-local fe80::/10
    if ((h[0] & 0xffc0) === 0xfec0) return true; // Deprecated Site-local fec0::/10
    if ((h[0] & 0xfe00) === 0xfc00) return true; // Unique Local fc00::/7
    if ((h[0] & 0xff00) === 0xff00) return true; // Multicast ff00::/8

    // Require Global Unicast range (2000::/3 -> first 3 bits 001)
    if ((h[0] & 0xe000) !== 0x2000) return true;

    return false;
  }
  return true;
}

export type DnsResolverFn = (
  hostname: string
) => Promise<ReadonlyArray<{ address: string; family: 4 | 6 }>>;

const defaultDnsResolver: DnsResolverFn = async (hostname) => {
  const res = await dns.lookup(hostname, { all: true, verbatim: true });
  return res.map((r) => ({ address: r.address, family: r.family as 4 | 6 }));
};

export function isAmbiguousIpv4Hostname(hostname: string): boolean {
  const clean = hostname.trim().toLowerCase();
  if (net.isIP(clean) === 4) return false; // Standard canonical dotted-quad is unambiguous
  // Reject integer/dword IPv4 (e.g. 2130706433), hex IPv4 (0x7f000001 or 0x7f.0.0.1),
  // octal IPv4 (0177.0.0.1), or short-form 2/3-part IPv4 (127.1, 127.0.1)
  if (/^(?:0x[0-9a-f]+|\d+)$/.test(clean)) return true;
  const parts = clean.split('.');
  if (parts.length >= 2 && parts.length <= 4 && parts.every((p) => /^(?:0x[0-9a-f]+|\d+)$/.test(p))) {
    return true;
  }
  return false;
}

/**
 * Validates URL scheme, credentials, port, and resolves DNS once, verifying that EVERY
 * returned A/AAAA record is a public global unicast IP (defeating mixed public/private DNS responses).
 * Returns a lookup function compatible with BOTH Node's `https.Agent` AND Undici's `Agent({ connect: { lookup } })`.
 */
export async function resolveAndPinSafeTarget(
  rawUrl: string,
  options: {
    allowedPorts?: ReadonlySet<number>;
    dnsResolver?: DnsResolverFn;
  } = {}
): Promise<{
  parsedUrl: URL;
  pinnedIp: string;
  pinnedFamily: 4 | 6;
  pinnedLookup: net.LookupFunction;
  httpsAgent: https.Agent;
}> {
  // Reject non-canonical raw authority/hostname tricks before or after WHATWG URL normalization
  const rawHostMatch = /^https:\/\/([^/?#]+)/i.exec(rawUrl.trim());
  if (rawHostMatch) {
    const rawHostOnly = rawHostMatch[1].split(':')[0].replace(/^\[|\]$/g, '');
    if (isAmbiguousIpv4Hostname(rawHostOnly)) {
      throw new Error(`SSRF_BLOCKED: Ambiguous octal/hex/dword/short IPv4 hostname "${rawHostOnly}" is forbidden`);
    }
  }

  let parsedUrl: URL;
  try {
    parsedUrl = new URL(rawUrl);
  } catch {
    throw new Error('SSRF_BLOCKED: Malformed URL');
  }

  if (parsedUrl.protocol !== 'https:') {
    throw new Error(`SSRF_BLOCKED: Protocol "${parsedUrl.protocol}" is forbidden; only https: is permitted`);
  }
  if (parsedUrl.username || parsedUrl.password) {
    throw new Error('SSRF_BLOCKED: Embedded URL credentials are forbidden');
  }

  const allowedPorts = options.allowedPorts ?? new Set([443]);
  const effectivePort = parsedUrl.port ? Number(parsedUrl.port) : 443;
  if (!Number.isInteger(effectivePort) || !allowedPorts.has(effectivePort)) {
    throw new Error(`SSRF_BLOCKED: Outbound port ${effectivePort} is not permitted`);
  }

  // Handle IP literal in hostname directly (e.g. https://127.0.0.1/ or https://[::1]/)
  const cleanHost = parsedUrl.hostname.replace(/^\[|\]$/g, '');
  if (isAmbiguousIpv4Hostname(cleanHost)) {
    throw new Error(`SSRF_BLOCKED: Ambiguous IPv4 hostname "${cleanHost}" is forbidden`);
  }

  const literalVersion = net.isIP(cleanHost);
  let records: ReadonlyArray<{ address: string; family: 4 | 6 }>;

  if (literalVersion === 4 || literalVersion === 6) {
    records = [{ address: cleanHost, family: literalVersion }];
  } else {
    const resolver = options.dnsResolver ?? defaultDnsResolver;
    try {
      records = await resolver(cleanHost);
    } catch {
      throw new Error('SSRF_BLOCKED: DNS resolution failed');
    }
  }

  if (!records || records.length === 0) {
    throw new Error('SSRF_BLOCKED: Hostname did not resolve to any address');
  }

  // CRITICAL: Validate EVERY resolved record! If a domain returns [93.184.216.34, 127.0.0.1], reject immediately!
  for (const rec of records) {
    if (isPrivateOrReservedIp(rec.address)) {
      throw new Error(`SSRF_BLOCKED: Hostname resolved to restricted/private IP ${rec.address}`);
    }
  }

  const pinnedIp = records[0].address;
  const pinnedFamily = records[0].family;

  const pinnedLookup: net.LookupFunction = (_hostname, lookupOpts, callback) => {
    if (typeof lookupOpts === 'object' && lookupOpts !== null && 'all' in lookupOpts && lookupOpts.all) {
      (
        callback as unknown as (
          err: NodeJS.ErrnoException | null,
          addresses: Array<{ address: string; family: number }>
        ) => void
      )(null, [{ address: pinnedIp, family: pinnedFamily }]);
      return;
    }
    callback(null, pinnedIp, pinnedFamily);
  };

  const httpsAgent = new https.Agent({
    keepAlive: false,
    servername: cleanHost,
    rejectUnauthorized: true,
    minVersion: 'TLSv1.2',
    lookup: pinnedLookup,
  });

  return { parsedUrl, pinnedIp, pinnedFamily, pinnedLookup, httpsAgent };
}

const SENSITIVE_OUTBOUND_HEADERS = new Set([
  'authorization',
  'cookie',
  'proxy-authorization',
  'x-api-key',
  'x-apigateway-api-userinfo',
]);

const SAFE_CROSS_ORIGIN_REDIRECT_HEADERS = new Set([
  'accept',
  'accept-language',
  'user-agent',
]);

/**
 * Transport-Matched, DNS-Pinned Safe HTTPS Fetcher with Hop-by-Hop Redirect Re-Validation,
 * Cross-Origin Redirect Header Stripping, Hard Total Wall-Clock Deadline (`DEVIL-17`),
 * and Streaming Response-Size Cutoff.
 */
export async function executePinnedSafeHttpsRequest(params: {
  url: string;
  method?: 'GET' | 'POST' | 'PUT' | 'DELETE';
  headers?: Readonly<Record<string, string>>;
  bodyBuffer?: Buffer;
  maxRedirects?: number;
  timeoutMs?: number;
  totalDeadlineMs?: number;
  maxResponseBytes?: number;
  dnsResolver?: DnsResolverFn;
  allowTestTransportOverride?: boolean;
  transportOverride?: (hop: {
    parsedUrl: URL;
    pinnedIp: string;
    headers: Record<string, string>;
    signal: AbortSignal;
  }) => Promise<{ statusCode: number; headers: Record<string, string>; body: Buffer }>;
}): Promise<{
  statusCode: number;
  headers: Record<string, string>;
  body: Buffer;
  finalUrl: string;
  pinnedIpUsed: string;
}> {
  if (params.transportOverride) {
    if (params.allowTestTransportOverride !== true || process.env.NODE_ENV === 'production') {
      throw new Error(
        'SSRF_TRANSPORT_OVERRIDE_FORBIDDEN: transportOverride requires allowTestTransportOverride === true and non-production runtime'
      );
    }
  }

  const maxRedirects = params.maxRedirects ?? 3;
  const timeoutMs = params.timeoutMs ?? 5_000;
  const totalDeadlineMs = params.totalDeadlineMs ?? timeoutMs;
  const maxResponseBytes = params.maxResponseBytes ?? 2 * 1024 * 1024; // 2MB max response
  const startedAtMs = Date.now();

  // Never forward Authorization, Cookie, or internal gateway headers to untrusted external URLs,
  // and reject any header key/value containing CR, LF, or Null bytes (CRLF injection guard).
  let currentSafeHeaders: Record<string, string> = {};
  for (const [k, v] of Object.entries(params.headers ?? {})) {
    if (/[\r\n\0]/.test(k) || /[\r\n\0]/.test(v)) {
      throw new Error('SSRF_HEADER_INJECTION_BLOCKED: Outbound header contains CR/LF/Null');
    }
    if (!SENSITIVE_OUTBOUND_HEADERS.has(k.toLowerCase())) {
      currentSafeHeaders[k] = v;
    }
  }

  let initialOrigin: string;
  try {
    initialOrigin = new URL(params.url).origin;
  } catch {
    throw new Error('SSRF_BLOCKED: Malformed URL');
  }
  let currentUrl = params.url;
  let currentMethod = params.method ?? 'GET';
  let currentBody = params.bodyBuffer;

  const deadlineController = new AbortController();
  const hardDeadlineTimer = setTimeout(() => {
    deadlineController.abort(new Error(`SSRF_HARD_DEADLINE_EXCEEDED: Exceeded total deadline of ${totalDeadlineMs}ms`));
  }, totalDeadlineMs);

  try {
    for (let redirectCount = 0; redirectCount <= maxRedirects; redirectCount++) {
      const elapsedMs = Date.now() - startedAtMs;
      const remainingDeadlineMs = totalDeadlineMs - elapsedMs;
      if (remainingDeadlineMs <= 0 || deadlineController.signal.aborted) {
        throw new Error(`SSRF_HARD_DEADLINE_EXCEEDED: Exceeded total deadline of ${totalDeadlineMs}ms`);
      }

      // Re-validate and DNS-pin EVERY hop (initial request + each redirect Location target)
      const pinned = await resolveAndPinSafeTarget(currentUrl, {
        dnsResolver: params.dnsResolver,
      });

      // DEVIL-09 Guard: If a redirect crossed to a different origin, strip all custom/application headers!
      if (pinned.parsedUrl.origin !== initialOrigin) {
        const strippedHeaders: Record<string, string> = {};
        for (const [hk, hv] of Object.entries(currentSafeHeaders)) {
          if (SAFE_CROSS_ORIGIN_REDIRECT_HEADERS.has(hk.toLowerCase())) {
            strippedHeaders[hk] = hv;
          }
        }
        currentSafeHeaders = strippedHeaders;
      }

      const requestHeaders: Record<string, string> = {
        ...currentSafeHeaders,
        Host: pinned.parsedUrl.host,
      };

      const hopTimeoutMs = Math.min(timeoutMs, Math.max(1, totalDeadlineMs - (Date.now() - startedAtMs)));

      const hopResponse = params.transportOverride
        ? await Promise.race([
            params.transportOverride({
              parsedUrl: pinned.parsedUrl,
              pinnedIp: pinned.pinnedIp,
              headers: requestHeaders,
              signal: deadlineController.signal,
            }),
            new Promise<never>((_, reject) => {
              const onAbort = () =>
                reject(
                  deadlineController.signal.reason ??
                    new Error(`SSRF_HARD_DEADLINE_EXCEEDED: Exceeded total deadline of ${totalDeadlineMs}ms`)
                );
              if (deadlineController.signal.aborted) {
                onAbort();
                return;
              }
              deadlineController.signal.addEventListener('abort', onAbort, { once: true });
            }),
          ])
        : await new Promise<{ statusCode: number; headers: Record<string, string>; body: Buffer }>(
            (resolve, reject) => {
              const req = https.request(
                {
                  protocol: 'https:',
                  hostname: pinned.parsedUrl.hostname,
                  port: pinned.parsedUrl.port || 443,
                  path: `${pinned.parsedUrl.pathname}${pinned.parsedUrl.search}`,
                  method: currentMethod,
                  headers: requestHeaders,
                  agent: pinned.httpsAgent,
                  servername: pinned.parsedUrl.hostname,
                  timeout: hopTimeoutMs,
                  signal: deadlineController.signal,
                },
                (res) => {
                  const chunks: Buffer[] = [];
                  let totalBytes = 0;

                  res.on('data', (chunk: Buffer) => {
                    if (Date.now() - startedAtMs > totalDeadlineMs) {
                      req.destroy(
                        new Error(`SSRF_HARD_DEADLINE_EXCEEDED: Exceeded total deadline of ${totalDeadlineMs}ms`)
                      );
                      return;
                    }
                    totalBytes += chunk.byteLength;
                    if (totalBytes > maxResponseBytes) {
                      req.destroy(
                        new Error(`SSRF_RESPONSE_TOO_LARGE: Exceeded ${maxResponseBytes} bytes`)
                      );
                      return;
                    }
                    chunks.push(chunk);
                  });

                  res.on('end', () => {
                    if (totalBytes > maxResponseBytes) return;
                    const normHeaders: Record<string, string> = {};
                    for (const [hk, hv] of Object.entries(res.headers)) {
                      if (typeof hv === 'string') normHeaders[hk.toLowerCase()] = hv;
                      else if (Array.isArray(hv)) normHeaders[hk.toLowerCase()] = hv.join(', ');
                    }
                    resolve({
                      statusCode: res.statusCode ?? 500,
                      headers: normHeaders,
                      body: Buffer.concat(chunks),
                    });
                  });

                  res.on('error', reject);
                }
              );

              req.on('timeout', () => {
                req.destroy(new Error('SSRF_REQUEST_TIMEOUT'));
              });
              req.on('error', reject);

              if (currentBody && currentBody.byteLength > 0) {
                req.write(currentBody);
              }
              req.end();
            }
          );

      if (hopResponse.body.byteLength > maxResponseBytes) {
        throw new Error(`SSRF_RESPONSE_TOO_LARGE: Exceeded ${maxResponseBytes} bytes`);
      }

      const status = hopResponse.statusCode;
      if (status === 301 || status === 302 || status === 303 || status === 307 || status === 308) {
        if (redirectCount >= maxRedirects) {
          throw new Error(`SSRF_MAX_REDIRECTS_EXCEEDED: Exceeded ${maxRedirects} redirects`);
        }
        const locationHeader = hopResponse.headers['location'] ?? hopResponse.headers['Location'];
        if (!locationHeader || /[\r\n\0]/.test(locationHeader)) {
          throw new Error('SSRF_REDIRECT_ERROR: Redirect response missing or invalid Location header');
        }
        const nextParsed = new URL(locationHeader, pinned.parsedUrl);
        const nextUrl = nextParsed.toString();
        if (
          nextParsed.origin !== initialOrigin &&
          (status === 307 || status === 308) &&
          currentBody &&
          currentBody.byteLength > 0
        ) {
          throw new Error(
            'SSRF_CROSS_ORIGIN_BODY_REDIRECT_BLOCKED: Refusing to forward request body across cross-origin 307/308 redirect'
          );
        }
        currentUrl = nextUrl;
        if (status === 301 || status === 302 || status === 303 || nextParsed.origin !== initialOrigin) {
          currentMethod = 'GET';
          currentBody = undefined;
        }
        continue;
      }

      return {
        statusCode: hopResponse.statusCode,
        headers: hopResponse.headers,
        body: hopResponse.body,
        finalUrl: pinned.parsedUrl.toString(),
        pinnedIpUsed: pinned.pinnedIp,
      };
    }

    throw new Error(`SSRF_MAX_REDIRECTS_EXCEEDED: Exceeded ${maxRedirects} redirects`);
  } finally {
    clearTimeout(hardDeadlineTimer);
  }
}
```

### Proxy & Network-Level Egress Controls
- **Outbound Proxy Warning (`HTTP_PROXY` / `HTTPS_PROXY`)**: If your runtime routes outbound requests through a corporate HTTP proxy, the proxy resolves DNS on its side unless configured otherwise. Enforce SSRF IP blocklists on the outbound proxy itself (e.g., Envoy / Squid ACLs) and apply VPC Egress Firewall rules blocking outbound connections from application subnets to RFC 1918 and `169.254.169.254/32`.

---

## 3. Remediated Proxy IP Extraction (`extractTrustedClientIpByCidr`)

### Why Fixed Proxy-Hop Counts Are Vulnerable
Counting `chain.length - trustedProxyHopCount` without verifying that `socketRemoteAddress` and intermediate hops actually belong to your trusted proxy CIDRs allows an attacker who connects directly to the service (or through a different ingress path) to spoof `X-Forwarded-For`!

```typescript
function ipv4ToUint32(ip: string): number | null {
  if (net.isIP(ip) !== 4) return null;
  const [a, b, c, d] = ip.split('.').map(Number);
  return (((a << 24) >>> 0) | (b << 16) | (c << 8) | d) >>> 0;
}

function ipv6ToBigInt(ip: string): bigint | null {
  const hextets = parseIpv6Hextets(ip);
  if (!hextets) return null;
  let val = 0n;
  for (const h of hextets) {
    val = (val << 16n) | BigInt(h);
  }
  return val;
}

export function isIpInCidr(rawIp: string, cidr: string): boolean {
  const ip = rawIp.trim();
  const [rangeIp, prefixStr] = cidr.trim().split('/');
  const prefixLen = Number(prefixStr);
  const ipVer = net.isIP(ip);
  const rangeVer = net.isIP(rangeIp);

  if (ipVer === 0 || ipVer !== rangeVer || !Number.isInteger(prefixLen)) {
    return false;
  }

  if (ipVer === 4) {
    if (prefixLen < 0 || prefixLen > 32) return false;
    const ipNum = ipv4ToUint32(ip)!;
    const rangeNum = ipv4ToUint32(rangeIp)!;
    const mask = prefixLen === 0 ? 0 : (~0 << (32 - prefixLen)) >>> 0;
    return (ipNum & mask) === (rangeNum & mask);
  }

  if (prefixLen < 0 || prefixLen > 128) return false;
  const ipBig = ipv6ToBigInt(ip);
  const rangeBig = ipv6ToBigInt(rangeIp);
  if (ipBig === null || rangeBig === null) return false;
  if (prefixLen === 0) return true;
  const shift = BigInt(128 - prefixLen);
  return (ipBig >> shift) === (rangeBig >> shift);
}

export function isTrustedProxyIp(ip: string, trustedProxyCidrs: readonly string[]): boolean {
  return trustedProxyCidrs.some((cidr) => isIpInCidr(ip, cidr));
}

/**
 * CIDR-Verified Right-to-Left Client IP Extractor:
 * 1. Verifies that the immediate TCP peer (`socketRemoteAddress`) belongs to `trustedProxyCidrs`.
 *    If not, `X-Forwarded-For` is untrusted and ignored immediately.
 * 2. Parses `X-Forwarded-For` and rejects malformed/ambiguous chains (failing closed to `socketRemoteAddress`).
 * 3. Walks right-to-left across the chain, skipping hops that belong to `trustedProxyCidrs`,
 *    and returns the first IP outside `trustedProxyCidrs` (the true client IP that connected to our edge).
 */
export function extractTrustedClientIpByCidr(params: {
  socketRemoteAddress: string;
  xForwardedForHeader?: string;
  trustedProxyCidrs: readonly string[];
}): string {
  const peerIp = params.socketRemoteAddress.trim();
  if (net.isIP(peerIp) === 0) {
    throw new Error(`INVALID_SOCKET_PEER_IP: "${params.socketRemoteAddress}"`);
  }

  // 1. If the immediate socket peer is NOT a trusted proxy, never trust X-Forwarded-For!
  if (!isTrustedProxyIp(peerIp, params.trustedProxyCidrs)) {
    return peerIp;
  }

  if (!params.xForwardedForHeader || params.xForwardedForHeader.trim().length === 0) {
    return peerIp;
  }

  const rawEntries = params.xForwardedForHeader.split(',').map((s) => s.trim());
  // 2. Reject malformed or ambiguous X-Forwarded-For chains (every entry must be a valid IPv4/IPv6 literal)
  for (const entry of rawEntries) {
    if (!entry || net.isIP(entry) === 0) {
      throw new Error(`MALFORMED_X_FORWARDED_FOR_CHAIN: Invalid IP entry "${entry}"`);
    }
  }

  // 3. Walk right-to-left: the first IP that is NOT in trustedProxyCidrs is the untrusted external client
  for (let i = rawEntries.length - 1; i >= 0; i--) {
    const hopIp = rawEntries[i];
    if (!isTrustedProxyIp(hopIp, params.trustedProxyCidrs)) {
      return hopIp;
    }
  }

  // All IPs in the chain were internal trusted proxies; return the leftmost trusted hop
  return rawEntries[0];
}
```

---

## 4. Anti-Prototype-Pollution Input Sanitizer & Serialized Keyed HMAC Audit Chain (`DEVIL-11` Hardened)

```typescript
import crypto from 'node:crypto';

const FORBIDDEN_OBJECT_KEYS = new Set(['__proto__', 'constructor', 'prototype']);

export function sanitizeUntrustedJsonInput(
  input: unknown,
  options: { maxDepth?: number; maxKeysPerObject?: number; forbidDollarKeys?: boolean } = {},
  currentDepth = 0
): unknown {
  const maxDepth = options.maxDepth ?? 12;
  const maxKeys = options.maxKeysPerObject ?? 250;
  const forbidDollar = options.forbidDollarKeys ?? true;

  if (currentDepth > maxDepth) {
    throw new Error(`PAYLOAD_REJECTED: JSON nesting depth exceeds maximum of ${maxDepth}`);
  }
  if (input === null || input === undefined) return input;
  if (typeof input === 'string') {
    if (input.includes('\0')) throw new Error('PAYLOAD_REJECTED: Null byte in string');
    return input.normalize('NFKC');
  }
  if (typeof input !== 'object') return input;

  if (Array.isArray(input)) {
    if (input.length > 1000) {
      throw new Error('PAYLOAD_REJECTED: Array length exceeds maximum bound');
    }
    return input.map((item) => sanitizeUntrustedJsonInput(item, options, currentDepth + 1));
  }

  const entries = Object.entries(input as Record<string, unknown>);
  if (entries.length > maxKeys) {
    throw new Error(`PAYLOAD_REJECTED: Object key count exceeds maximum of ${maxKeys}`);
  }

  const cleanObj: Record<string, unknown> = Object.create(null);
  for (const [rawKey, value] of entries) {
    const key = rawKey.normalize('NFKC');
    if (FORBIDDEN_OBJECT_KEYS.has(key)) {
      throw new Error(`PAYLOAD_REJECTED: Prototype pollution key "${key}" is forbidden`);
    }
    if (forbidDollar && (key.startsWith('$') || key.includes('.'))) {
      throw new Error(`PAYLOAD_REJECTED: NoSQL operator or dotted key "${key}" is forbidden`);
    }
    cleanObj[key] = sanitizeUntrustedJsonInput(value, options, currentDepth + 1);
  }
  return { ...cleanObj };
}

export function computeAuditChainHash(params: {
  auditHmacSecret: string;
  sequenceNumber: bigint;
  prevHashHex: string;
  tenantId: string;
  actorId: string;
  action: string;
  resourceType: string;
  resourceId: string;
  payloadJson: string;
  createdAtIsoUtc: string;
}): string {
  if (params.auditHmacSecret.length < 32) {
    throw new Error('AUDIT_CHAIN_ERROR: auditHmacSecret must be at least 32 characters');
  }
  const fields = [
    params.sequenceNumber.toString(),
    params.prevHashHex,
    params.tenantId,
    params.actorId,
    params.action,
    params.resourceType,
    params.resourceId,
    params.payloadJson,
    params.createdAtIsoUtc,
  ];
  const canonical = fields.map((f) => `${Buffer.byteLength(f, 'utf8')}:${f};`).join('');
  return crypto.createHmac('sha256', params.auditHmacSecret).update(canonical, 'utf8').digest('hex');
}
```

---

## 5. Verification & Test Requirements

1. **SSRF Private IPv4, IPv6, Mapped IPv6, Mixed DNS & DNS Rebinding Tests (`TEST-14`, `TEST-15`, `TEST-16`)**:
   - Assert `isPrivateOrReservedIp` blocks `127.0.0.1`, `10.0.0.1`, `169.254.169.254`, `::1`, `fe80::1`, `::ffff:169.254.169.254`, `::ffff:7f00:1`, `64:ff9b::a9fe:a9fe`, `2001:0000::1`, and `100::1`.
   - Assert `resolveAndPinSafeTarget` rejects a domain that returns mixed public + private DNS records (`['93.184.216.34', '127.0.0.1']`).
   - Assert `executePinnedSafeHttpsRequest` connects strictly to the pinned IP from the initial resolution without performing a second DNS lookup.
2. **Redirect-Based SSRF, Non-HTTPS Scheme, Port & Oversized Response Tests (`TEST-17`)**:
   - Assert that an HTTPS endpoint returning `302 Location: https://internal.example.com/` (resolving to `10.0.0.5` or `http://example.com/`) is blocked during redirect re-validation.
   - Assert that responses exceeding `maxResponseBytes` or ports other than `443` fail closed.
3. **CIDR Proxy IP Extraction Tests**:
   - Assert that if `socketRemoteAddress` is `198.51.100.25` (outside `trustedProxyCidrs: ['10.0.0.0/8']`), `X-Forwarded-For: 1.2.3.4` is ignored and `198.51.100.25` is returned.
   - Assert that malformed `X-Forwarded-For: 1.2.3.4, not-an-ip, 10.0.1.5` throws `MALFORMED_X_FORWARDED_FOR_CHAIN`.

### Authoritative References
- **OWASP Server-Side Request Forgery Prevention Cheat Sheet**: https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html
- **Node.js `https.request` & `net.Socket` Lookup Documentation**: https://nodejs.org/api/https.html#httpsrequesturl-options-callback
- **IANA IPv4 & IPv6 Special-Purpose Address Registries**: https://www.iana.org/assignments/iana-ipv6-special-registry/iana-ipv6-special-registry.xhtml
