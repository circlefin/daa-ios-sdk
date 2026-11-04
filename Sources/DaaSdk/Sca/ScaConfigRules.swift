// Copyright (c) 2026, Circle Internet Group, Inc. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Configuration rules for the SCA ceremony.
//
// The redirect rules mirror the checks Circle's hosted ceremony page and the
// Android SDK apply to the same URI. They are not the authority (Circle's
// own check when it registers your redirect URIs is), but a URI this rejects
// would be rejected there too, and failing at construction is cheaper than
// failing in the sheet.
//
// The rules work on the raw string before handing it to `URLComponents`,
// because Foundation's parser has changed leniency across OS releases (iOS 17
// started percent-encoding invalid characters instead of refusing them), and
// the page builds its callback from the raw string, not from a parsed URL.

import Foundation

enum ScaConfigRules {
    // The ceremony origins. Each must equal the WebAuthn origin Circle
    // verifies `clientDataJSON.origin` against, byte for byte.
    static func origin(for environment: DaaEnvironment) -> String {
        switch environment {
        case .sandbox: return "https://daa-sca-sandbox.circle.com"
        case .production: return "https://daa-sca.circle.com"
        }
    }

    private static let circleDomain = "circle.com"

    // Schemes a browser would act on itself rather than hand to the app, or
    // that execute content. Kept identical to the page's list so the two never
    // disagree, even where a scheme only matters on Android.
    private static let forbiddenSchemes: Set<String> = [
        "http", "javascript", "data", "vbscript", "blob", "file", "about", "ftp", "ws", "wss",
        "filesystem", "intent", "content", "chrome", "android-app", "mailto", "tel"
    ]

    /// A bare, lowercase `https://<host>` origin on `circle.com` or one of its
    /// subdomains: no port, path, query, fragment, or credentials. The origin
    /// is compared as a string by the server, so anything that would need
    /// normalizing is refused rather than normalized.
    static func isValidOrigin(_ origin: String) -> Bool {
        let prefix = "https://"
        guard origin.hasPrefix(prefix) else {
            return false
        }
        let host = origin.dropFirst(prefix.count)
        let labels = host.split(separator: ".", omittingEmptySubsequences: false)
        guard host == circleDomain || host.hasSuffix("." + circleDomain),
              host.utf8.count <= 253,
              labels.allSatisfy(isDNSLabel)
        else {
            return false
        }
        return true
    }

    // The server refuses a longer `redirectUri`, so a ceremony could never
    // be opened for one.
    static let maxRedirectURILength = 2048

    static func isValidRedirectURI(_ redirectURI: String) -> Bool {
        // A fragment is where the result goes; a URI that already has one —
        // even a bare trailing `#` — would be ambiguous.
        guard redirectURI.utf8.count <= maxRedirectURILength,
              let scheme = rawScheme(of: redirectURI),
              !redirectURI.contains(ScaCallback.fragmentDelimiter),
              let components = URLComponents(string: redirectURI),
              components.user == nil, components.password == nil,
              isStableInBrowser(redirectURI, scheme: scheme)
        else {
            return false
        }
        if scheme == "https" {
            // No port, not even `:443`: the system matches an https callback by
            // host and path only, and the domain's association file is served
            // from the default port, so a URI with a port could be registered
            // with Circle yet never be delivered back to the app.
            return !(components.host ?? "").isEmpty && !hasExplicitPort(redirectURI)
        }
        return !forbiddenSchemes.contains(scheme)
    }

    // The page navigates with `window.location = redirectUri + '#…'`, so the
    // callback the session sees is the browser's WHATWG URL serialization of
    // the raw string, and `ScaCallback` compares it with the configured URI
    // nearly literally. Each rule refuses one thing that serialization
    // rewrites and the RFC 3986 character check lets through. Everything else
    // the character check admits comes back unchanged; in particular WHATWG
    // never decodes a percent-encoded unreserved character (`%7E`, `%41`)
    // outside the host, so those are accepted.
    private static func isStableInBrowser(_ uri: String, scheme: String) -> Bool {
        let rest = uri[uri.index(after: uri.firstIndex(of: ":") ?? uri.startIndex)...]
        let hierarchy = rest.prefix { $0 != "?" }
        let query = rest.dropFirst(hierarchy.count)
        var path = hierarchy
        var host: Substring?
        if hierarchy.hasPrefix("//") {
            let authority = hierarchy.dropFirst(2).prefix { $0 != "/" }
            host = authority
            path = hierarchy.dropFirst(2 + authority.count)
        }
        // Path state drops `.` and resolves `..` segments, matching `%2e` in
        // any case as a dot. A path that does not start with `/` after a
        // custom scheme is an opaque path, which WHATWG leaves as written.
        if path.hasPrefix("/"), path.split(separator: "/").contains(where: isDotSegment) {
            return false
        }
        guard scheme == "https" else {
            return true
        }
        // The special-query percent-encode set adds `'` for special schemes
        // (https) only; a custom scheme's query keeps it.
        if query.contains("'") {
            return false
        }
        // The host parser percent-decodes a special scheme's host, and
        // re-serializes an IPv4 or IPv6 literal in canonical form (`0x7f.1`
        // becomes `127.0.0.1`). An IP literal cannot serve the associated
        // domain file an https callback needs anyway. Uppercase is refused too:
        // the parser lowercases it, and the session's https callback is
        // registered with the host as written, so it must already be the form
        // the browser navigates to (as the scheme must already be lowercase).
        guard let host else {
            return true
        }
        return !host.contains("%") && !host.hasPrefix("[") && !endsInANumber(host)
            && host == host.lowercased()
    }

    // A single-dot or double-dot path segment, as WHATWG path state reads it.
    private static func isDotSegment(_ segment: Substring) -> Bool {
        [".", "%2e", "..", ".%2e", "%2e.", "%2e%2e"].contains(segment.lowercased())
    }

    // WHATWG "ends in a number": the last label (ignoring one trailing empty
    // label) is all digits or a `0x` hex number, which sends the host to the
    // IPv4 parser.
    private static func endsInANumber(_ host: Substring) -> Bool {
        var labels = host.split(separator: ".", omittingEmptySubsequences: false)
        if labels.count > 1, labels.last?.isEmpty == true {
            labels.removeLast()
        }
        guard let last = labels.last?.lowercased(), !last.isEmpty else {
            return false
        }
        if last.allSatisfy({ ("0"..."9").contains($0) }) {
            return true
        }
        return last.hasPrefix("0x") && last.dropFirst(2).allSatisfy(\.isHexDigit)
    }

    // Whether the authority (between `//` and the first `/`, `?` or end)
    // names a port. Read from the raw string: `URLComponents.port` is nil for
    // an empty port such as `https://host:/cb`.
    private static func hasExplicitPort(_ value: String) -> Bool {
        guard let start = value.range(of: "//")?.upperBound else {
            return false
        }
        let authority = value[start...].prefix { $0 != "/" && $0 != "?" }
        return authority.contains(":")
    }

    // The scheme exactly as written, or nil unless the whole string is
    // printable RFC 3986 characters and the scheme is lowercase RFC 3986
    // grammar. Lowercase only, as the page, the Android SDK, and Circle's check
    // of your registered redirect URIs require, so they never disagree about
    // whether a URI matches. The character check also refuses leading
    // whitespace, which a WHATWG `URL` would silently strip.
    private static func rawScheme(of value: String) -> String? {
        guard value.unicodeScalars.allSatisfy(isURIScalar),
              let colon = value.firstIndex(of: ":")
        else {
            return nil
        }
        let scheme = value[..<colon]
        guard let first = scheme.unicodeScalars.first, ("a"..."z").contains(first),
              scheme.unicodeScalars.allSatisfy(isLowercaseSchemeScalar)
        else {
            return nil
        }
        return String(scheme)
    }

    private static let uriPunctuation = Set("-._~:/?#[]@!$&'()*+,;=%".unicodeScalars)

    private static func isURIScalar(_ scalar: Unicode.Scalar) -> Bool {
        isASCIIAlphanumeric(scalar) || uriPunctuation.contains(scalar)
    }

    private static func isLowercaseSchemeScalar(_ scalar: Unicode.Scalar) -> Bool {
        ("a"..."z").contains(scalar) || ("0"..."9").contains(scalar) || "+.-".unicodeScalars.contains(scalar)
    }

    private static func isASCIIAlphanumeric(_ scalar: Unicode.Scalar) -> Bool {
        ("a"..."z").contains(scalar) || ("A"..."Z").contains(scalar) || ("0"..."9").contains(scalar)
    }

    // A lowercase LDH label: 1–63 of `[a-z0-9-]`, not starting or ending
    // with a hyphen.
    private static func isDNSLabel(_ label: Substring) -> Bool {
        guard (1...63).contains(label.utf8.count), label.first != "-", label.last != "-" else {
            return false
        }
        return label.unicodeScalars.allSatisfy { ("a"..."z").contains($0) || ("0"..."9").contains($0) || $0 == "-" }
    }
}
