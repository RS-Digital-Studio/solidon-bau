// Die Hülle des Bau-Repositorys für die Signierjobs auf dem Mac.
//
// Dieselbe Hülle wie in bau.py — AES-256-GCM in Blöcken, Nonce aus Präfix,
// Blocknummer und Schlussbit, der Vorspann als authentisierte Angabe —, aber
// ohne Python und ohne fremde Pakete: Ein Job mit entsperrtem Signierschlüssel
// führt nur Apples eigene Werkzeuge aus, und CryptoKit gehört zum System.
// bau.py crosscheck prüft beide Fassungen gegeneinander, bevor ein Signierjob
// sie braucht.
//
//     box seal|open <art> <eingang> <ausgang>
//
// Schlüssel, Artefaktname, Commit und Lauf kommen aus der Umgebung
// (SOLIDON_BAU_KEY, SOLIDON_ARTIFACT, SOLIDON_SHA, SOLIDON_NONCE).

import CryptoKit
import Foundation

let magic = Data("SOLIDON-BAU-1\n".utf8)
let block = 4 * 1024 * 1024
let tagSize = 16
let prefixSize = 7

struct Refusal: Error {
    let message: String
}

func environment(_ name: String) throws -> String {
    guard let value = ProcessInfo.processInfo.environment[name], !value.isEmpty else {
        throw Refusal(message: "\(name) fehlt — Schritt der Kiste prüfen.")
    }
    return value
}

func checked(_ value: String, _ what: String) throws -> String {
    let allowed = Set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-")
    guard !value.isEmpty, value.count <= 200, value.allSatisfy({ allowed.contains($0) }) else {
        throw Refusal(message: "Ungültige Angabe für \(what) — Aufruf prüfen.")
    }
    return value
}

func nibble(_ character: UInt8) -> UInt8? {
    switch character {
    case 48...57: return character - 48
    case 97...102: return character - 87
    default: return nil
    }
}

func hexData(_ text: String) -> Data? {
    let characters = Array(text.utf8)
    guard characters.count % 2 == 0 else { return nil }
    var bytes = [UInt8]()
    var index = 0
    while index < characters.count {
        guard let high = nibble(characters[index]), let low = nibble(characters[index + 1]) else {
            return nil
        }
        bytes.append(high << 4 | low)
        index += 2
    }
    return Data(bytes)
}

func hexString(_ data: Data) -> String {
    return data.map { String(format: "%02x", $0) }.joined()
}

func nonce(_ prefix: Data, _ index: UInt32, _ last: Bool) throws -> AES.GCM.Nonce {
    var bytes = prefix
    withUnsafeBytes(of: index.bigEndian) { bytes.append(contentsOf: $0) }
    bytes.append(last ? 1 : 0)
    return try AES.GCM.Nonce(data: bytes)
}

func readExactly(_ handle: FileHandle, _ count: Int) throws -> Data {
    var data = Data()
    while data.count < count {
        guard let chunk = try handle.read(upToCount: count - data.count), !chunk.isEmpty else {
            break
        }
        data.append(chunk)
    }
    return data
}

func writer(_ url: URL) throws -> FileHandle {
    guard FileManager.default.createFile(atPath: url.path, contents: nil) else {
        throw Refusal(message: "\(url.path) lässt sich nicht anlegen.")
    }
    return try FileHandle(forWritingTo: url)
}

func sealBox(input: URL, output: URL, kind: String, name: String, commit: String, run: String, key: SymmetricKey) throws {
    let reader = try FileHandle(forReadingFrom: input)
    defer { try? reader.close() }
    let target = try writer(output)
    defer { try? target.close() }
    var generator = SystemRandomNumberGenerator()
    let prefix = Data((0..<prefixSize).map { _ in UInt8.random(in: 0...255, using: &generator) })
    let fields = "{\"block\":\(block),\"commit\":\"\(commit)\",\"format\":1,\"kind\":\"\(kind)\","
        + "\"name\":\"\(name)\",\"prefix\":\"\(hexString(prefix))\",\"run\":\"\(run)\"}"
    let header = Data(fields.utf8)
    var associated = magic
    withUnsafeBytes(of: UInt32(header.count).bigEndian) { associated.append(contentsOf: $0) }
    associated.append(header)
    try target.write(contentsOf: associated)
    var index: UInt32 = 0
    var current = try readExactly(reader, block)
    while true {
        var following = Data()
        if current.count == block {
            following = try readExactly(reader, block)
        }
        let last = following.isEmpty
        let chunkNonce = try nonce(prefix, index, last)
        let box = try AES.GCM.seal(current, using: key, nonce: chunkNonce, authenticating: associated)
        try target.write(contentsOf: box.ciphertext)
        try target.write(contentsOf: box.tag)
        if last {
            return
        }
        current = following
        index += 1
    }
}

func openBox(input: URL, output: URL, kind: String, name: String, commit: String, run: String, key: SymmetricKey) throws {
    let reader = try FileHandle(forReadingFrom: input)
    defer { try? reader.close() }
    let head = try readExactly(reader, magic.count + 4)
    guard head.count == magic.count + 4, Data(head.prefix(magic.count)) == magic else {
        throw Refusal(message: "Keine Solidon-Hülle — Datei und Artefakt prüfen.")
    }
    let size = Data(head.suffix(4)).reduce(0) { $0 << 8 | Int($1) }
    guard size > 0, size <= 4096 else {
        throw Refusal(message: "Der Kopf der Hülle ist beschädigt — Artefakt neu erzeugen.")
    }
    let header = try readExactly(reader, size)
    guard header.count == size,
          let fields = try JSONSerialization.jsonObject(with: header) as? [String: Any],
          (fields["format"] as? Int) == 1,
          (fields["block"] as? Int) == block,
          let prefixText = fields["prefix"] as? String,
          let prefix = hexData(prefixText), prefix.count == prefixSize
    else {
        throw Refusal(message: "Der Kopf der Hülle ist beschädigt — Artefakt neu erzeugen.")
    }
    guard (fields["kind"] as? String) == kind, (fields["name"] as? String) == name,
          (fields["commit"] as? String) == commit, (fields["run"] as? String) == run
    else {
        throw Refusal(message: "Die Hülle gehört zu einem anderen Artefakt, Commit oder Lauf.")
    }
    let associated = head + header
    let target = try writer(output)
    defer { try? target.close() }
    var index: UInt32 = 0
    var current = try readExactly(reader, block + tagSize)
    while true {
        var following = Data()
        if current.count == block + tagSize {
            following = try readExactly(reader, block + tagSize)
        }
        let last = following.isEmpty
        guard current.count >= tagSize else {
            throw Refusal(message: "Die Hülle ist abgeschnitten — Artefakt neu erzeugen.")
        }
        let chunkNonce = try nonce(prefix, index, last)
        let plain: Data
        do {
            let sealed = try AES.GCM.SealedBox(
                nonce: chunkNonce,
                ciphertext: Data(current.prefix(current.count - tagSize)),
                tag: Data(current.suffix(tagSize))
            )
            plain = try AES.GCM.open(sealed, using: key, authenticating: associated)
        } catch {
            throw Refusal(message: "Die Hülle ist verändert oder mit einem anderen Schlüssel verschlossen.")
        }
        try target.write(contentsOf: plain)
        if last {
            return
        }
        current = following
        index += 1
    }
}

do {
    let arguments = CommandLine.arguments
    guard arguments.count == 5, arguments[1] == "seal" || arguments[1] == "open" else {
        throw Refusal(message: "Aufruf: box seal|open <art> <eingang> <ausgang>")
    }
    let keyText = try environment("SOLIDON_BAU_KEY")
        .trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
    guard keyText.count == 64, let keyData = hexData(keyText) else {
        throw Refusal(message: "Der Schlüssel ist kein 64-stelliger Hexwert.")
    }
    let key = SymmetricKey(data: keyData)
    let kind = try checked(arguments[2], "Art")
    let name = try checked(try environment("SOLIDON_ARTIFACT"), "Artefakt")
    let commit = try checked(try environment("SOLIDON_SHA"), "Commit")
    let run = try checked(try environment("SOLIDON_NONCE"), "Lauf")
    let input = URL(fileURLWithPath: arguments[3])
    let output = URL(fileURLWithPath: arguments[4])
    if arguments[1] == "seal" {
        try sealBox(input: input, output: output, kind: kind, name: name, commit: commit, run: run, key: key)
    } else {
        try openBox(input: input, output: output, kind: kind, name: name, commit: commit, run: run, key: key)
    }
} catch let refusal as Refusal {
    FileHandle.standardError.write(Data(("Angehalten: " + refusal.message + "\n").utf8))
    exit(1)
} catch {
    FileHandle.standardError.write(Data("Angehalten: \(error)\n".utf8))
    exit(1)
}
