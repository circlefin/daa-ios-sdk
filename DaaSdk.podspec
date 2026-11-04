# Copyright (c) 2026, Circle Internet Group, Inc. All rights reserved.
#
# SPDX-License-Identifier: Apache-2.0
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# DaaSdk — CocoaPods spec for the Digital Asset Accounts (DAA) iOS SDK.
#
# This repository is a CocoaPods spec source. Add it to a Podfile:
#   source 'https://github.com/circlefin/daa-ios-sdk.git'
#   pod 'DaaSdk'
#
# The root spec is what `:git` / `:path` consumers resolve directly.
# `Specs/DaaSdk/<version>/DaaSdk.podspec` is the spec-source copy CocoaPods
# reads when this repository is a Podfile `source`, and must stay
# byte-identical to this file at the current version. Both compile
# `Sources/DaaSdk/**` from source; there is no prebuilt xcframework.
#
# `s.source` pins the `v<version>` release tag, not a moving branch.
# `:branch` or `:path` (local checkout) remain the paths for iterating on an
# unmerged change; neither is a release pin.
#
# Keep `s.version` locked to `DaaSdk.version` in Sources/DaaSdk/DaaSdk.swift.

Pod::Spec.new do |s|
  s.name     = 'DaaSdk'
  s.version  = '0.7.1' # x-release-please-version
  s.summary  = 'Swift SDK for Circle Digital Asset Accounts (DAA) on iOS.'
  s.description = <<~DESC
    Swift SDK for Circle Digital Asset Accounts (DAA) on iOS 15 and later.
    It keeps an installation-scoped P-256 AuthKey in the Secure Enclave,
    signs validated DAA device authorizations with it, and presents
    Circle's hosted passkey ceremony for strong customer authentication.
    It makes no network calls. CocoaPods installs it from its own git spec
    source, not from the public CocoaPods Specs repository.
  DESC

  s.homepage = 'https://github.com/circlefin/daa-ios-sdk'
  s.license  = { :type => 'Apache-2.0', :file => 'LICENSE' }
  s.author   = 'CIRCLE'
  s.source   = {
    :git => 'https://github.com/circlefin/daa-ios-sdk.git',
    :tag => "v#{s.version}"
  }

  s.ios.deployment_target = '15.0'
  s.swift_version         = '5.9'
  s.module_name           = 'DaaSdk'
  s.frameworks            = 'Security', 'LocalAuthentication', 'CryptoKit'

  s.source_files = 'Sources/DaaSdk/**/*.swift'

  # Match Package.swift's StrictConcurrency upcoming feature so the
  # CocoaPods compile is not a weaker dialect than SwiftPM.
  s.pod_target_xcconfig = {
    'OTHER_SWIFT_FLAGS' => '$(inherited) -enable-upcoming-feature StrictConcurrency'
  }
end
