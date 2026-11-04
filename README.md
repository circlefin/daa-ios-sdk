# DaaSdk (daa-ios-sdk)

Swift SDK for **Digital Asset Accounts (DAA)** — attested authentication and
self-custody DAA API access on iOS.

> **Scope.** This package provides an installation-scoped Secure Enclave P-256
> AuthKey, validated exact device-authorization signing, wire encoders, and a
> presentation client for Circle's hosted passkey ceremony (`DaaSca`). To add
> passkey approval to a native app, go to
> [Passkey SCA](#passkey-sca-strong-customer-authentication).
> This package makes no network calls. Social login, AuthKey device
> enrollment, HTTP transport, REST clients, response models, pagination,
> sessions and Owner grants are out of scope; for passkey SCA, your backend
> talks to Circle.

## Features

- `Package.swift` — SwiftPM package `DaaSdk` with one library product `DaaSdk`.
- `DaaSdk.podspec` and `Specs/DaaSdk/<version>/` — CocoaPods packaging (see
  [CocoaPods](#cocoapods-git-spec-source)).
- `Sources/DaaSdk/DaaSdk.swift` — package namespace and `DaaSdk.version`.
- `Sources/DaaSdk/AuthKey/` — internal P-256 SPKI/thumbprint and strict
  DER-to-JOSE representation helpers.
- `Sources/DaaSdk/SecureKey/` — the public DAA-specific AuthKey actor and its
  validated signing-input type plus the internal Secure Enclave backend.
- `Sources/DaaSdk/Registration/` — the two pre-Prepare primitives:
  `DaaSecureRandom.bytes(count:)` over the platform CSPRNG, and the ephemeral
  per-attempt `DaaRegistrationFlowKey`, which exports its public key as DER SPKI
  and signs a typed registration authorization at Complete. **The flow key is
  not an AuthKey**: it is never persisted, never enters the Keychain or Secure
  Enclave, and has no generic `sign(bytes)`.
- `Sources/DaaSdk/PrepareReceipt/` — `DaaPrepareReceiptSignature.verify`, the
  ES256 check of the DAA-signed Prepare receipt against a pinned X9.63 public
  key. CryptoKit does the verification; the type is verify-only and holds no
  private key.
- `Sources/DaaSdk/Sca/` — `DaaSca`, which presents Circle's hosted SCA
  ceremony in an ephemeral `ASWebAuthenticationSession` and relays its result
  unchanged. It holds no key material and signs nothing. Its configuration
  accepts only the `sandbox` and `production` environments.
- `Tests/DaaSdkTests/` — XCTest coverage consuming the canonical cross-language
  AuthKey wire fixture.

**CocoaPods installs `DaaSdk` from this repository.** `DaaSdk` is not in the
public CocoaPods Specs repository (`cdn.cocoapods.org`). This repository is a
CocoaPods spec source, so you add it as a `source` in your `Podfile`, or point
`:git` at it. See [Install](#install).

**Not in this package:** AuthKey device enrollment, sessions, compact-JWS
claim construction, recovery, and rotation. There is no HTTP transport and no
typed DAA API surface in this package. Passkey enrollment for SCA is
supported: see [Passkey SCA](#passkey-sca-strong-customer-authentication).

## Layout

```
Package.swift                        SwiftPM manifest (swift-tools-version 5.9)
DaaSdk.podspec                       Root CocoaPods spec (compiles Sources/)
Specs/DaaSdk/<version>/              CocoaPods spec-source copy per release
Sources/DaaSdk/DaaSdk.swift          Package namespace and version
Sources/DaaSdk/AuthKey/              Internal pure wire encoders
Sources/DaaSdk/SecureKey/            Public AuthKey actor + internal backend
Sources/DaaSdk/Registration/         CSPRNG + ephemeral flow key
Sources/DaaSdk/PrepareReceipt/       Verify-only Prepare receipt ES256 check
Sources/DaaSdk/Sca/                  Hosted SCA ceremony client
Conformance/AuthKeyWireV1.json       Canonical cross-SDK conformance fixture
Tests/DaaSdkTests/                   Tests + byte-identical fixture resource
.swiftlint.yml                       SwiftLint configuration
```

## Install

Use SwiftPM for a native app. Use CocoaPods if your app already uses it, for
example a React Native app.

### SwiftPM

<!-- x-release-please-start-version -->

```swift
.package(url: "https://github.com/circlefin/daa-ios-sdk.git", from: "0.7.1")
```

<!-- x-release-please-end -->

Each release is tagged `v<version>`. A versioned `from:` / `exact:` pin
resolves once the matching tag exists.

```swift
.package(url: "https://github.com/circlefin/daa-ios-sdk.git", branch: "master")
```

Use `branch: "master"` only for iterating on unreleased work, not as a
release pin: `master` moves, so a build pinned to it is not reproducible.

### CocoaPods (git spec source)

This repository **is** the spec source, the same pattern as
[`w3s-ios-sdk`](https://github.com/circlefin/w3s-ios-sdk). In the host app's
`Podfile`:

```ruby
source 'https://github.com/circlefin/daa-ios-sdk.git'
source 'https://cdn.cocoapods.org/'

pod 'DaaSdk'
```

`:git` / `:path` consumers resolve the root `DaaSdk.podspec` and compile the
same `Sources/DaaSdk/**` tree (no prebuilt xcframework):

<!-- x-release-please-start-version -->

```ruby
# Tag (release pin — use this)
pod 'DaaSdk', :git => 'https://github.com/circlefin/daa-ios-sdk.git', :tag => 'v0.7.1'

# Branch (a moving target — for iterating on unreleased work only, not a release pin)
pod 'DaaSdk', :git => 'https://github.com/circlefin/daa-ios-sdk.git', :branch => 'master'

# Local checkout (also for iterating on unreleased work, not a release pin)
pod 'DaaSdk', :path => '../daa-ios-sdk'
```

<!-- x-release-please-end -->

A new version's `Specs/DaaSdk/<version>/` can appear before its `v<version>`
tag exists. In that short window the spec-source form (`source '...git'` +
`pod 'DaaSdk'`) can select the new spec and fail to fetch it, and a `:tag` pin
does not resolve yet. Both forms work once the tag exists, so confirm it
exists before you pin to it.

## Passkey SCA (strong customer authentication)

`DaaSca` shows Circle's passkey ceremony in your iOS app, so your end users can
register a passkey and approve sensitive operations, such as a transfer, with
it.

The ceremony is a page served from Circle's own origin. `DaaSca` opens it in
the system authentication browser (`ASWebAuthenticationSession`), never in a
web view, so your app does not see or draw what the user approves. This
package holds no credentials and makes no calls to Circle's APIs. Your backend
does that with the Circle Node SDK,
[`@circle-fin/daa-node-sdk`](https://github.com/circlefin/daa-node-sdk/blob/master/packages/node/README.md).

- [Prerequisites](#prerequisites)
- [Requirements](#requirements)
- [Choosing the callback](#choosing-the-callback)
- [Quick start](#quick-start)
- [End-to-end sequence](#end-to-end-sequence)
- [Configuration](#configuration)
- [Running one ceremony at a time](#running-one-ceremony-at-a-time)
- [Error handling](#error-handling)
- [Security checklist](#security-checklist)

### Prerequisites

- **Circle registers your callback URI.** Tell Circle the exact redirect URI
  your app will use in each environment (for example
  `com.example.app.sca://callback`). Register every URI you plan to use, such
  as a custom scheme and an `https` one.
- **Your backend sends the same URI.** When your backend opens a registration
  or a challenge with the
  [Circle Node SDK](https://github.com/circlefin/daa-node-sdk), it passes that
  URI as `redirectUri`. Matching is by exact string: the value in
  `DaaScaConfiguration`, the backend's `redirectUri`, and the URI Circle
  registered must be identical, including case and any trailing slash. If they
  differ, or the URI was never registered, the backend's request fails with
  error `420068` (`SCA_REDIRECT_URI_NOT_ALLOWED`) and no `frameToken` is
  issued.

### Requirements

| Feature | Minimum iOS |
| --- | --- |
| Showing the ceremony sheet | iOS 15 (the package minimum) |
| Passkeys in the ceremony | iOS 16 |
| An `https` callback URI | iOS 17.4 |

`sca.capabilities().isCeremonySupported` tells you whether a ceremony can
succeed on the current device with your configuration. Check it before you
offer passkey approval. `true` is necessary but not sufficient: the device may
still have no passcode or no passkey provider, which the ceremony reports as
`unsupported`.

Add the package as described in [Install](#install). Then
`import DaaSdk`.

### Choosing the callback

The callback URI is where Circle's page sends the result.
`ASWebAuthenticationSession` intercepts it and hands it straight to `DaaSca`.
The callback is matched against the URI as written, so write it in the form a
browser navigates to: no `.` or `..` path segments (including `%2e` forms).
`DaaScaConfiguration` refuses a URI the browser would rewrite with
`invalidRedirectURI`.

- **Custom scheme (default).** For example `com.example.app.sca://callback`.
  Works on every supported iOS version. The session catches the callback
  itself, so you do **not** add a `CFBundleURLTypes` entry or an `onOpenURL`
  / `application(_:open:options:)` handler for it. The scheme must be
  lowercase.
- **`https` callback (iOS 17.4 and later).** For example
  `https://app.example.com/sca/callback`, on a domain you own. Your app needs
  the **`webcredentials:`** Associated Domain for that host (for example
  `webcredentials:app.example.com`), not `applinks:`, and the domain must
  serve an `apple-app-site-association` file that lists your app under
  `webcredentials`. If the `webcredentials` entry or the file is missing, the
  callback is not delivered and the call ends when the deadline passes.
  The URI must not include a port (not even `:443`): the system matches the
  callback by host and path, so `DaaScaConfiguration` refuses one with
  `invalidRedirectURI`. The host must be a lowercase domain name, not an IP
  address, and any `'` in the query must be written as `%27`. It also refuses an
  `https` URI on iOS versions before 17.4 with `httpsCallbackUnavailable`, so
  choose by availability:

  ```swift
  func scaRedirectURI() -> String {
      if #available(iOS 17.4, *) {
          return "https://app.example.com/sca/callback"
      }
      return "com.example.app.sca://callback"
  }
  ```

  Your backend must send the same choice as `redirectUri`, so pass it along
  with the request that opens the ceremony.

### Quick start

`DaaSca` runs the device half. Your backend runs the rest with the Node SDK.
In the examples below, `MyBackend` stands for your own API client and is not
part of this package.

```swift
import DaaSdk

/// Your own backend API, not part of DaaSdk.
protocol MyBackend: Sendable {
    /// Opens a passkey registration and returns its frameToken. The backend
    /// keeps the registrationId.
    func startPasskeyRegistration() async throws -> String
    func completePasskeyRegistration(registrationResponse: String) async throws
    /// Opens a challenge for the transfer and returns its frameToken. The
    /// backend keeps the challengeId against the transfer.
    func startTransfer(_ transferId: String) async throws -> String
    func confirmTransfer(_ transferId: String, assertion: String) async throws
}

@MainActor
final class Passkeys {
    private let sca: DaaSca
    private let backend: any MyBackend

    init(backend: any MyBackend) throws {
        sca = DaaSca(configuration: try DaaScaConfiguration(
            environment: .sandbox,
            redirectURI: "com.example.app.sca://callback"
        ))
        self.backend = backend
    }

    var isAvailable: Bool {
        sca.capabilities().isCeremonySupported
    }

    /// Registers a passkey for the signed-in user.
    func enroll() async throws {
        let frameToken = try await backend.startPasskeyRegistration()
        let registrationResponse = try await sca.enroll(frameToken: frameToken)
        // Send the result to your backend unchanged.
        try await backend.completePasskeyRegistration(registrationResponse: registrationResponse)
    }

    /// Approves one transfer with the user's passkey.
    func approveTransfer(_ transferId: String) async throws {
        let frameToken = try await backend.startTransfer(transferId)
        let assertion = try await sca.approve(frameToken: frameToken)
        // Send the assertion to your backend unchanged.
        try await backend.confirmTransfer(transferId, assertion: assertion)
    }
}
```

`approve(frameToken:)` and `enroll(frameToken:)` present over the key window
of the foreground scene, which suits SwiftUI:

```swift
import SwiftUI

struct ApproveTransferButton: View {
    let passkeys: Passkeys
    let transferId: String
    @State private var isRunning = false

    var body: some View {
        Button("Approve with passkey") {
            isRunning = true
            Task {
                defer { isRunning = false }
                // Handle errors as shown in Error handling below.
                try? await passkeys.approveTransfer(transferId)
            }
        }
        .disabled(isRunning || !passkeys.isAvailable)
    }
}
```

If no foreground scene has a key window at the call — as can happen for a
moment right after a system sheet such as a biometric prompt dismisses —
those calls wait up to two seconds for one before opening the ceremony, so
you do not need to retry yourself. The wait counts against the ceremony
deadline, and nothing is presented until a window is found. If none appears
in time, they throw `sessionUnavailable`. With several windows open (iPad, Mac), or in UIKit,
pass the window to present over:

```swift
import DaaSdk
import UIKit

@MainActor
func approve(with sca: DaaSca, frameToken: String, from view: UIView) async throws -> String {
    guard let window = view.window else {
        throw DaaScaError.sessionUnavailable(message: "The view is not in a window")
    }
    return try await sca.approve(frameToken: frameToken, presentationAnchor: window)
}
```

### End-to-end sequence

Approving an operation (step-up):

1. **The app** asks your backend to start the operation, for example
   `startTransfer(transferId)`.
2. **Your backend** calls `daa.passkeys.openChallenge(...)` with the request
   it intends to send and your `redirectUri`. It keeps the returned
   `challengeId` against that transfer and returns only the `frameToken` to
   the app. The app never needs the `challengeId`.
3. **The app** calls `sca.approve(frameToken:)`. It returns the assertion as a
   string.
4. The app sends that string, unmodified, with its own reference to the
   operation (for example `confirmTransfer(transferId, assertion)`) to your
   backend over your own authenticated channel.
5. **Your backend** sends the original request to Circle again, with the same
   body, and two extra headers: `X-Sca-Challenge-Id` (the `challengeId` it
   stored) and `X-Sca-Assertion` (the string from step 3, as is).

Registering a passkey:

1. **Your backend** calls `daa.passkeys.createRegistration(...)` with your
   `redirectUri`. It keeps the `registrationId` (for example in the user's
   session) and returns only the `frameToken` to the app.
2. **The app** calls `sca.enroll(frameToken:)` and sends the returned string,
   unmodified, to your backend.
3. **Your backend** parses that string as JSON once and passes the result as
   `attestationResponse` to `daa.passkeys.complete(...)`, together with the
   `registrationId` it kept. Do not modify or rebuild the object.

**Detecting "not enrolled".** The ceremony has no "not enrolled" result.
Before opening a challenge, have your backend list the user's passkeys
(`daa.passkeys.list(...)`). If none is active, run enrollment instead.

A challenge is valid for five minutes and a registration for ten. Your backend
opens a new challenge or registration for every attempt, including each
retry.

### Configuration

`DaaScaConfiguration` is validated when you create it and throws
`DaaScaConfigurationError`, so a misconfiguration fails at startup rather than
mid-ceremony.

| Parameter | Required | Default | Description |
| --- | --- | --- | --- |
| `environment` | Yes | | `.sandbox` or `.production`. Use the same environment as your backend. |
| `redirectURI` | Yes | | Your registered callback URI. A lowercase custom scheme, or `https` on iOS 17.4 and later. At most 2048 characters. |
| `circleOrigin` | No | | Overrides the ceremony origin. Leave it unset unless Circle gives you a host for a Circle test environment. Allowed only with `.sandbox`. |
| `approveTimeout` | No | `300` | Seconds an `approve` ceremony may stay open before the SDK dismisses it and throws `expired`. From `30` to `3600` (one hour); anything else throws `invalidCeremonyTimeout`. |
| `enrollTimeout` | No | `600` | The same for `enroll`, with the same range. |

| `environment` | Ceremony origin |
| --- | --- |
| `.sandbox` | `https://daa-sca-sandbox.circle.com` |
| `.production` | `https://daa-sca.circle.com` |

### Running one ceremony at a time

Starting a new `approve` or `enroll` while one is open cancels the first: its
sheet is dismissed and its call throws `cancelled`. Disable the control that
starts a ceremony until the call returns, as in the SwiftUI example above.
Cancelling the Swift `Task` that awaits the call also dismisses the sheet and
throws `cancelled`.

### Error handling

Every failure from `approve` and `enroll` is a `DaaScaError`. Errors from your
own backend calls are not; handle them separately.

| Case | Meaning | What to do |
| --- | --- | --- |
| `cancelled` | The user declined or closed the sheet, or the call was replaced by a newer one, or its task was cancelled. Closing the page shown for an already-used or expired token is also `cancelled`. | Not an error state. Offer a retry. Your backend opens a **new** challenge or registration, stores the new `challengeId` or `registrationId`, and returns the new `frameToken`. Never reuse a `frameToken`. |
| `expired` | The token passed its lifetime, or the ceremony was still open at `approveTimeout` / `enrollTimeout`. | Retry once: your backend opens a **new** challenge or registration, stores the new `challengeId` or `registrationId`, and returns the new `frameToken`. |
| `unsupported` | The device or browser has no usable passkey authenticator. | Offer your non-passkey fallback. |
| `alreadyEnrolled` | The user already has a passkey (enrollment only). | Treat the user as enrolled and use `approve`. |
| `stateMismatch` | The callback did not belong to the ceremony this call opened. Nothing was relayed. | An integration bug. Report it with your SDK version. |
| `sessionUnavailable` | The sheet could not be shown: the callback cannot be delivered on this iOS version, the session would not start, or there was no usable window. | An integration or configuration bug. Check your callback setup and the window you present from. |
| `protocol` | The call or the callback broke the ceremony contract, for example a blank or malformed `frameToken`. | An integration bug. Retrying will not help. Update to the latest SDK version and contact Circle if it persists. |

`error.localizedDescription` is a fixed, developer-facing English sentence for
logs. It is not localized. Show your own, localized copy to users. The
`message` some cases carry is diagnostic text for logs, not for display.

```swift
import DaaSdk

@MainActor
func runApproval(
    _ passkeys: Passkeys,
    transferId: String,
    reportIntegrationBug: (DaaScaError) -> Void
) async {
    do {
        try await passkeys.approveTransfer(transferId)
    } catch DaaScaError.cancelled, DaaScaError.expired {
        // Offer a retry. The retry opens a new challenge.
    } catch DaaScaError.unsupported {
        // Offer your non-passkey fallback.
    } catch let error as DaaScaError {
        // stateMismatch, sessionUnavailable, protocol: integration bugs.
        reportIntegrationBug(error)
    } catch {
        // A failure from your own backend call.
    }
}
```

### Security checklist

- **Keep your Circle API key on your backend.** This package does not need it.
- **Treat the `frameToken` as a secret.** It is a one-time capability for one
  pending ceremony. Fetch it over your own authenticated channel, and do not
  log, store, or put it in a URL. Never reuse one: every attempt gets a new
  token from your backend.
- **Send the results unmodified.** Forward the `approve` assertion and the
  `enroll` registration response to your backend exactly as returned. Do not
  parse and re-serialize them in the app, and do not log them.
- **Authenticate the hop to your backend.** The endpoints that receive these
  results must confirm the signed-in user is the one the ceremony was opened
  for.
- **Send the same request you opened the challenge for.** The retried request
  must carry the same body as the one passed to `openChallenge`. A different
  body needs a new challenge.
- **The user approves what Circle shows.** The details are loaded by the
  ceremony from Circle. Do not build your own confirmation screen from your
  backend's challenge response.

## Develop

```bash
swift build       # compile the package
swift test        # run unit tests
swiftlint lint --strict # lint — CI fails on warnings and errors
```

`swift build`, `swift test`, and `swiftlint lint --strict` are the full
verification loop. To contribute, see [`CONTRIBUTING.md`](CONTRIBUTING.md).

## References

- The canonical AuthKey wire fixture is `Conformance/AuthKeyWireV1.json`. iOS
  and Android are verified against the same bytes, so an integrator can check
  their own implementation against it too.
- Reporting a security vulnerability: [`SECURITY.md`](SECURITY.md).
- Contributing: [`CONTRIBUTING.md`](CONTRIBUTING.md).

## License

[Apache License 2.0](LICENSE)
