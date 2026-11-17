import Foundation

/// The dashboard's connection to the engine: `selfguard bridge`, a child process that serves the
/// JSON API over stdio (one JSON object per line each way; see src/bridge.ts). There is no
/// network involved.
///
/// - Started lazily by the first request, and again by the next one if it dies (requests in
///   flight then fail with a clear error).
/// - Stopped 60 s after the dashboard window closes (`windowClosed`), and when the app quits.
///   The engine exits by itself when its stdin closes, which also happens if the app dies.
actor Bridge {
    /// What the page gets back: `{status, data}` or `{status, error: {code, message}}`.
    struct Reply: @unchecked Sendable {
        let value: [String: Any]
    }

    static let idleStop: TimeInterval = 60

    private let engine: Engine
    private var process: Process?
    private var input: FileHandle?
    private var pending: [Int: CheckedContinuation<Reply, Never>] = [:]
    private var nextID = 1
    private var stopTask: Task<Void, Never>?
    private let running = ProcessBox()

    init(engine: Engine) {
        self.engine = engine
        signal(SIGPIPE, SIG_IGN) // a dead engine must be an error to handle, not a crash
    }

    static func failure(_ status: Int, _ code: String, _ message: String) -> Reply {
        Reply(value: ["status": status, "error": ["code": code, "message": message]])
    }

    /// Send one API request and wait for its answer. Never throws: failures are replies.
    func request(method: String, path: String, body: [String: Any]) async -> Reply {
        stopTask?.cancel()
        stopTask = nil
        guard let input = input ?? launch() else {
            return Self.failure(503, "engine_unavailable", "The selfguard engine could not be started.")
        }
        let id = nextID
        nextID += 1
        guard var line = try? JSONSerialization.data(withJSONObject: ["id": id, "method": method, "path": path, "body": body] as [String: Any]) else {
            return Self.failure(400, "invalid", "The request could not be encoded.")
        }
        line.append(0x0A)
        return await withCheckedContinuation { done in
            pending[id] = done
            do {
                try input.write(contentsOf: line)
            } catch {
                pending[id] = nil
                done.resume(returning: Self.failure(503, "engine_stopped", "The selfguard engine stopped. Try again."))
            }
        }
    }

    /// The dashboard window closed: stop the engine process after a minute unless it is used again.
    func windowClosed() {
        stopTask?.cancel()
        stopTask = Task {
            try? await Task.sleep(nanoseconds: UInt64(Self.idleStop * 1_000_000_000))
            guard !Task.isCancelled else { return }
            stopIfIdle()
        }
    }

    func windowOpened() {
        stopTask?.cancel()
        stopTask = nil
    }

    /// App quit: stop the engine now (callable from anywhere, it does not wait for the actor).
    nonisolated func terminateNow() { running.terminate() }

    // MARK: - Process

    private func stopIfIdle() {
        guard pending.isEmpty else { return windowClosed() } // a long request is still running
        guard let p = process else { return }
        process = nil
        try? input?.close() // EOF: the engine finishes and exits
        input = nil
        Task.detached {
            try? await Task.sleep(nanoseconds: 3_000_000_000)
            if p.isRunning { p.terminate() }
        }
    }

    private func launch() -> FileHandle? {
        let p = Process()
        let stdin = Pipe()
        let stdout = Pipe()
        p.executableURL = engine.node
        p.arguments = engine.arguments(["bridge"])
        p.standardInput = stdin
        p.standardOutput = stdout
        p.standardError = FileHandle.nullDevice
        p.environment = engine.environment
        // Output events in order: lines, then nil at EOF (the process is gone).
        let (events, feed) = AsyncStream.makeStream(of: Data?.self)
        let splitter = LineSplitter()
        stdout.fileHandleForReading.readabilityHandler = { handle in
            let data = handle.availableData
            if data.isEmpty {
                handle.readabilityHandler = nil
                feed.yield(nil)
                feed.finish()
            } else {
                for line in splitter.feed(data) { feed.yield(line) }
            }
        }
        do { try p.run() } catch { return nil }
        process = p
        input = stdin.fileHandleForWriting
        running.set(p)
        Task {
            for await event in events {
                if let line = event { received(line) } else { lost(p) }
            }
        }
        return input
    }

    private func received(_ line: Data) {
        guard let object = try? JSONSerialization.jsonObject(with: line) as? [String: Any],
              let id = object["id"] as? Int,
              let done = pending.removeValue(forKey: id)
        else { return } // not an answer to a request of ours (e.g. a protocol error for a bad line)
        var reply: [String: Any] = ["status": object["status"] as? Int ?? 500]
        if let data = object["data"] { reply["data"] = data }
        if let error = object["error"] { reply["error"] = error }
        done.resume(returning: Reply(value: reply))
    }

    /// The process ended: fail what was waiting for it. The next request starts a new one.
    private func lost(_ p: Process) {
        guard process === p else { return } // one we stopped on purpose
        process = nil
        input = nil
        let waiting = pending
        pending = [:]
        for (_, done) in waiting {
            done.resume(returning: Self.failure(503, "engine_stopped", "The selfguard engine stopped unexpectedly. Try again."))
        }
    }
}

/// Splits a byte stream into lines. Used from one readability handler at a time.
private final class LineSplitter: @unchecked Sendable {
    private var buffer = Data()

    func feed(_ data: Data) -> [Data] {
        buffer.append(data)
        var lines: [Data] = []
        while let newline = buffer.firstIndex(of: 0x0A) {
            lines.append(Data(buffer[buffer.startIndex..<newline]))
            buffer = Data(buffer[(newline + 1)...])
        }
        return lines
    }
}

/// The running engine process, reachable without awaiting the actor (for `terminateNow`).
private final class ProcessBox: @unchecked Sendable {
    private let lock = NSLock()
    private var process: Process?

    func set(_ p: Process) {
        lock.lock()
        process = p
        lock.unlock()
    }

    func terminate() {
        lock.lock()
        let p = process
        lock.unlock()
        if let p, p.isRunning { p.terminate() }
    }
}
