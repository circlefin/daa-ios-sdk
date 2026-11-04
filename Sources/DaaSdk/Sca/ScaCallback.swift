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

// Reads the ceremony page's redirect back into a result.
//
// The page navigates to `<redirectURI>#v=1&state=…&kind=result&ceremony=…&
// payload=…` or `…&kind=error&code=…&message=…`, where `code` is one of
// `Cancelled | Expired | Unsupported | AlreadyEnrolled`. The result is in the
// fragment so it never reaches a server access log if an `https` callback
// falls through to the web.
//
// Everything here fails closed. The callback is size-bounded before it is
// read; every key must be one the page writes for that kind, at most once;
// the version must be exactly 1; and the payload must be bounded, canonical
// Base64URL, strict UTF-8, and a JSON object with no repeated top-level
// member. The payload text is then handed through untouched. It does not
// look inside the WebAuthn response: the server verifies that, and a client
// that reshaped it would break the exact-bytes relay the backend depends on,
// since the text becomes the `X-Sca-Assertion` header value as is. The wire
// format is shared with the Android SDK and Circle's hosted ceremony page.

import Foundation

enum ScaCallback {
    static let protocolVersion = 1

    // The largest response the server accepts is an enrollment: an
    // attestation object of up to 32 KiB plus client data of up to 8 KiB,
    // each Base64URL inside the JSON. 64 KiB of JSON holds that with room for
    // the other members.
    static let maxPayloadBytes = 64 * 1024

    // Base64URL of `maxPayloadBytes`, plus the redirect URI (at most 2048)
    // and the short envelope keys, rounded up.
    static let maxCallbackLength = 96 * 1024

    // The diagnostic on the `expired` the SDK raises itself at the ceremony
    // deadline, so logs can tell it from the page's.
    static let deadlineMessage = "The ceremony deadline passed"

    // The page writes short fixed sentences. Anything longer is not one.
    static let maxMessageLength = 1024

    private static let resultKeys: Set<String> = ["v", "state", "kind", "ceremony", "payload"]
    private static let errorKeys: Set<String> = ["v", "state", "kind", "code", "message"]

    // `#`, written as a Unicode escape so this file contains no raw-string
    // opener, which the plain literal would be.
    static let fragmentDelimiter: Character = "\u{23}"

    /// The exact response JSON text, or the error the callback reports.
    static func parse(_ callback: String, for request: ScaCeremonyRequest) -> Result<String, DaaScaError> {
        // Bounded before anything else reads it.
        guard callback.utf8.count <= maxCallbackLength else {
            return protocolFailure("Callback exceeds the size limit")
        }
        guard let hash = callback.firstIndex(of: fragmentDelimiter) else {
            return protocolFailure("Callback carried no result")
        }
        guard sameTarget(String(callback[..<hash]), request.redirectURI) else {
            return protocolFailure("Callback did not arrive at the configured redirect URI")
        }
        guard let params = readParams(callback[callback.index(after: hash)...]) else {
            return protocolFailure("Callback fragment is malformed")
        }
        guard params["v"] == String(protocolVersion) else {
            return protocolFailure("Unsupported callback version")
        }
        // State ties this callback to the ceremony this client opened. Without
        // it, a stale callback from an earlier ceremony would be
        // indistinguishable from the real one. The page drops a state it would
        // not have echoed, so a missing one is a mismatch too.
        guard params["state"] == request.state else {
            return .failure(.stateMismatch)
        }

        return readKind(params, expected: request.kind)
    }

    // Each kind carries exactly the keys the page writes for it.
    private static func readKind(
        _ params: [String: String],
        expected: ScaCeremonyKind
    ) -> Result<String, DaaScaError> {
        let allowed: Set<String>
        switch params["kind"] {
        case "result": allowed = resultKeys
        case "error": allowed = errorKeys
        default: return protocolFailure("Unknown callback kind")
        }
        guard Set(params.keys).isSubset(of: allowed) else {
            return protocolFailure("Callback carried an unexpected parameter")
        }
        return allowed == resultKeys ? readResult(params, expected: expected) : readError(params)
    }

    private static func readResult(
        _ params: [String: String],
        expected: ScaCeremonyKind
    ) -> Result<String, DaaScaError> {
        guard params["ceremony"] == expected.rawValue else {
            return protocolFailure("Callback is for a different ceremony kind")
        }
        // Checked on the encoded length, so an oversized payload is never
        // decoded.
        guard let encoded = params["payload"],
              encoded.utf8.count <= (maxPayloadBytes * 4 + 2) / 3
        else {
            return protocolFailure("Callback payload is missing or exceeds the size limit")
        }
        guard let bytes = decodeCanonicalBase64URL(encoded) else {
            return protocolFailure("Callback payload is not Base64URL")
        }
        // The relayed text must be exactly the bytes the page encoded. A
        // leading BOM is refused outright: `JSON.stringify` never writes one,
        // and whether Foundation's decode keeps or drops it differs across OS
        // releases, so the outcome would otherwise depend on the device. The
        // round-trip check backstops any other silent change.
        guard !bytes.starts(with: [0xEF, 0xBB, 0xBF]),
              let text = String(bytes: bytes, encoding: .utf8), Data(text.utf8) == bytes
        else {
            return protocolFailure("Callback payload is not UTF-8")
        }
        guard (try? JSONSerialization.jsonObject(with: bytes)) is [String: Any] else {
            return protocolFailure("Callback payload is not a JSON object")
        }
        // A dictionary keeps one of two repeated members, but the relayed text
        // keeps both, and the server's parser may pick the other.
        guard !DuplicateJSONKeys.existAtTopLevel(bytes) else {
            return protocolFailure("Callback payload repeats a member")
        }
        return .success(text)
    }

    // Exactly the set the page redirects with. Failures from before the page
    // knows where to redirect cannot be sent, so anything outside the set is
    // off contract rather than mapped to a guess.
    private static func readError(_ params: [String: String]) -> Result<String, DaaScaError> {
        let message = params["message"]
        guard (message?.utf8.count ?? 0) <= maxMessageLength else {
            return protocolFailure("Callback message exceeds the size limit")
        }
        switch params["code"] {
        case "Cancelled": return .failure(.cancelled)
        case "Expired": return .failure(.expired(message: message))
        case "Unsupported": return .failure(.unsupported(message: message))
        case "AlreadyEnrolled": return .failure(.alreadyEnrolled(message: message))
        default: return protocolFailure("Unknown callback error code")
        }
    }

    // The browser, not this SDK, produced the part before `#`, so compare it
    // structurally: scheme and host are case-insensitive, an empty path after
    // a host is the same as `/`, and an explicit default https port is the
    // same as none, as on Android.
    private static func sameTarget(_ actual: String, _ configured: String) -> Bool {
        guard let lhs = URLComponents(string: actual), let rhs = URLComponents(string: configured),
              let lhsScheme = lhs.scheme, let rhsScheme = rhs.scheme,
              lhsScheme.lowercased() == rhsScheme.lowercased(),
              lhs.percentEncodedHost?.lowercased() == rhs.percentEncodedHost?.lowercased(),
              effectivePort(lhs) == effectivePort(rhs),
              lhs.percentEncodedUser == nil, lhs.percentEncodedPassword == nil,
              lhs.percentEncodedQuery == rhs.percentEncodedQuery
        else {
            return false
        }
        return normalizedPath(lhs) == normalizedPath(rhs)
    }

    private static let httpsDefaultPort = 443

    private static func effectivePort(_ components: URLComponents) -> Int? {
        components.port ?? (components.scheme?.lowercased() == "https" ? httpsDefaultPort : nil)
    }

    private static func normalizedPath(_ components: URLComponents) -> String {
        let path = components.percentEncodedPath
        return components.percentEncodedHost != nil && path.isEmpty ? "/" : path
    }

    // `key=decodeURIComponent(value)` pairs. A repeated key is rejected rather
    // than resolved first- or last-wins: two readers that pick differently
    // would disagree about what the page said. `removingPercentEncoding`
    // leaves `+` as a plus, which is encodeURIComponent semantics, and refuses
    // malformed escapes and non-UTF-8 results.
    private static func readParams(_ fragment: Substring) -> [String: String]? {
        guard !fragment.isEmpty else {
            return nil
        }
        var params: [String: String] = [:]
        for pair in fragment.split(separator: "&", omittingEmptySubsequences: false) {
            guard let equals = pair.firstIndex(of: "="), equals != pair.startIndex,
                  let value = pair[pair.index(after: equals)...].removingPercentEncoding
            else {
                return nil
            }
            let key = String(pair[..<equals])
            guard params.updateValue(value, forKey: key) == nil else {
                return nil
            }
        }
        return params
    }

    // Unpadded Base64URL that re-encodes to itself, so non-zero trailing bits,
    // padding, and the standard alphabet are all refused rather than
    // tolerated.
    private static func decodeCanonicalBase64URL(_ value: String) -> Data? {
        var base64 = value.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        guard value.utf8.allSatisfy({ !"+/=".utf8.contains($0) }), base64.count % 4 != 1 else {
            return nil
        }
        base64 += String(repeating: "=", count: (4 - base64.count % 4) % 4)
        guard let data = Data(base64Encoded: base64), Base64URL.encode(data) == value else {
            return nil
        }
        return data
    }

    private static func protocolFailure(_ message: String) -> Result<String, DaaScaError> {
        .failure(.protocol(message: message))
    }
}
