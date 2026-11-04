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

import Foundation
import XCTest

/// Reads the *code* of a `Sources/DaaSdk/<directory>/` file (`Registration`
/// by default) so a test can assert on what the source does not contain.
///
/// Swift cannot enumerate a struct's methods at runtime, so "no generic
/// `sign(bytes)` is reachable" and "nothing logs secret material" are pinned
/// against the source text instead of being left to review. Moving or renaming
/// a guarded file fails the test with the path it looked for, which is the
/// intended prompt to move the guard with it.
///
/// Comments are stripped and string-literal contents are blanked before
/// matching, because the guarded headers deliberately name the things the code
/// must not do — "no `sign(bytes)`", "not `arc4random`" — and matching that
/// prose would fail the guard for saying so.
///
/// Because this guard is the only enforcement of "no generic sign(bytes)" a
/// Swift test can reach, the stripper tracks string literals rather than cutting
/// at the first `//`. A naive cut is quietly wrong in both directions: a `//`
/// inside a literal would hide every token after it on that line, and a token
/// named inside a literal would be reported as if it were code. Constructs a
/// single-line scan cannot reason about — multi-line literals, raw strings, an
/// unterminated quote — throw rather than being parsed approximately.
enum RegistrationSourceGuard {
    enum ParseFailure: Error, Equatable {
        /// A `"""` literal spans lines, which a per-line scan cannot track.
        case multiLineStringLiteral
        /// A `#"…"#` raw string changes the escaping rules this scan assumes.
        case rawStringLiteral
        /// A line ends inside a literal, so the scan lost the quote state.
        case unterminatedStringLiteral(line: Int)
    }

    /// Strip comments and blank string-literal contents, keeping the quotes.
    ///
    /// Pure and directly unit-tested by `RegistrationSourceGuardTests`, so the
    /// mechanism the absence assertions rest on is itself verified rather than
    /// trusted.
    static func strippedCode(from source: String) throws -> String {
        guard !source.contains("\"\"\"") else {
            throw ParseFailure.multiLineStringLiteral
        }
        guard !source.contains("#\"") else {
            throw ParseFailure.rawStringLiteral
        }

        let lines = source.split(separator: "\n", omittingEmptySubsequences: false)
        return try lines.enumerated()
            .map { offset, sourceLine in
                guard let code = strippedLine(sourceLine) else {
                    throw ParseFailure.unterminatedStringLiteral(line: offset + 1)
                }
                return code
            }
            .joined(separator: "\n")
    }

    /// Strip one line, or return `nil` if it ends inside a string literal.
    private static func strippedLine(_ sourceLine: Substring) -> String? {
        var code = ""
        var isInsideLiteral = false
        var isEscaped = false

        for character in sourceLine {
            guard !isInsideLiteral else {
                // Literal contents are dropped; only the closing quote is kept.
                if isEscaped {
                    isEscaped = false
                } else if character == "\\" {
                    isEscaped = true
                } else if character == "\"" {
                    isInsideLiteral = false
                    code.append(character)
                }
                continue
            }
            if character == "/", code.last == "/" {
                code.removeLast()
                return code
            }
            if character == "\"" {
                isInsideLiteral = true
            }
            code.append(character)
        }
        return isInsideLiteral ? nil : code
    }

    /// The text between the named function's opening brace and its matching
    /// closing brace.
    static func functionBody(declaredBy declaration: String, in code: String) -> String? {
        guard let declaration = code.range(of: declaration),
              let open = code[declaration.upperBound...].firstIndex(of: "{") else {
            return nil
        }
        var depth = 0
        var index = open
        while index < code.endIndex {
            switch code[index] {
            case "{":
                depth += 1
            case "}":
                depth -= 1
                if depth == 0 {
                    return String(code[code.index(after: open)..<index])
                }
            default:
                break
            }
            index = code.index(after: index)
        }
        return nil
    }

    static func code(
        of fileName: String,
        inDirectory directory: String = "Registration",
        file: StaticString = #filePath,
        line: UInt = #line
    ) throws -> String {
        let contents = try contents(of: fileName, inDirectory: directory, file: file, line: line)
        do {
            return try strippedCode(from: contents)
        } catch {
            XCTFail(
                """
                \(fileName) contains a construct this guard cannot parse (\(error)). Teach the \
                stripper about it before relying on the absence assertions again — an \
                approximate parse can hide the very code the guard exists to catch.
                """,
                file: file,
                line: line
            )
            throw error
        }
    }

    private static func repositoryRoot() -> URL {
        // #filePath is <repo>/Tests/DaaSdkTests/<this file>.
        URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
    }

    private static func directoryURL(_ directory: String) -> URL {
        repositoryRoot()
            .appendingPathComponent("Sources", isDirectory: true)
            .appendingPathComponent("DaaSdk", isDirectory: true)
            .appendingPathComponent(directory, isDirectory: true)
    }

    private static func contents(
        of fileName: String,
        inDirectory directory: String,
        file: StaticString,
        line: UInt
    ) throws -> String {
        let source = directoryURL(directory).appendingPathComponent(fileName)

        guard FileManager.default.fileExists(atPath: source.path) else {
            XCTFail("Guarded source is not at \(source.path); move the guard with the file.", file: file, line: line)
            throw CocoaError(.fileNoSuchFile)
        }
        return try String(contentsOf: source, encoding: .utf8)
    }

    /// Every `.swift` file name directly under `Sources/DaaSdk/<directory>/`,
    /// listed from disk rather than hand-maintained, so every file in the
    /// directory is covered instead of silently skipped.
    static func swiftFileNames(
        inDirectory directory: String,
        file: StaticString = #filePath,
        line: UInt = #line
    ) throws -> [String] {
        let url = directoryURL(directory)
        guard let names = try? FileManager.default.contentsOfDirectory(atPath: url.path) else {
            XCTFail("Cannot list \(url.path); the guard has nothing to cover.", file: file, line: line)
            throw CocoaError(.fileNoSuchFile)
        }
        return names.filter { $0.hasSuffix(".swift") }.sorted()
    }

    static func assertAbsent(
        _ tokens: [String],
        from fileName: String,
        inDirectory directory: String = "Registration",
        because reason: String,
        file: StaticString = #filePath,
        line: UInt = #line
    ) throws {
        let code = try code(of: fileName, inDirectory: directory, file: file, line: line)
        for token in tokens {
            XCTAssertFalse(
                code.contains(token),
                "\(fileName) contains \"\(token)\": \(reason)",
                file: file,
                line: line
            )
        }
    }

    /// Like `assertAbsent`, but a hit only counts when `token` is not merely a
    /// substring of a longer identifier — e.g. `print(` inside `thumbprint(`.
    /// `Sources/DaaSdk/SecureKey` and `AuthKey` have legitimate identifiers
    /// like `jwkThumbprint(` that a plain substring check would misreport.
    static func assertAbsentAsToken(
        _ tokens: [String],
        from fileName: String,
        inDirectory directory: String,
        because reason: String,
        file: StaticString = #filePath,
        line: UInt = #line
    ) throws {
        let code = try code(of: fileName, inDirectory: directory, file: file, line: line)
        for token in tokens {
            XCTAssertFalse(
                containsAsToken(token, in: code),
                "\(fileName) contains \"\(token)\" as code, not just as a substring of a longer identifier: \(reason)",
                file: file,
                line: line
            )
        }
    }

    private static func containsAsToken(_ token: String, in code: String) -> Bool {
        var searchRange = code.startIndex..<code.endIndex
        while let range = code.range(of: token, range: searchRange) {
            let precedingCharIsIdentifier: Bool
            if range.lowerBound > code.startIndex {
                let previous = code[code.index(before: range.lowerBound)]
                precedingCharIsIdentifier = previous.isLetter || previous.isNumber || previous == "_"
            } else {
                precedingCharIsIdentifier = false
            }
            if !precedingCharIsIdentifier {
                return true
            }
            searchRange = range.upperBound..<code.endIndex
        }
        return false
    }
}
