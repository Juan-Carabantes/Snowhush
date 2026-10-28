import AppKit
import Security

/// Opened straight from the downloaded disk image, Snowhush copies itself to Applications,
/// ejects the image and starts again from there, so it never runs from a volume that goes away.
enum AppMover {
    /// Returns true when a copy in Applications is about to start and this instance should quit.
    static func moveIfNeeded() -> Bool {
        // A disk image mounts read-only; an external drive the user runs it from on purpose doesn't, and stays put.
        guard let source = originalBundleURL(), source.path.hasPrefix("/Volumes/"),
              (try? source.resourceValues(forKeys: [.volumeIsReadOnlyKey]))?.volumeIsReadOnly == true
        else { return false }
        let destination = URL(fileURLWithPath: "/Applications", isDirectory: true).appendingPathComponent(source.lastPathComponent)
        let files = FileManager.default
        // The copy is made and checked beside Applications first, so one that fails leaves the old app where it was.
        let staging: URL
        do {
            staging = try files.url(for: .itemReplacementDirectory, in: .userDomainMask, appropriateFor: destination, create: true)
        } catch {
            NSLog("Snowhush: could not move to Applications: \(error)")
            return false
        }
        defer { try? files.removeItem(at: staging) }
        let staged = staging.appendingPathComponent(source.lastPathComponent)
        do {
            try files.copyItem(at: source, to: staged)
            guard isSignedLikeSelf(staged) else {
                NSLog("Snowhush: the copy's code signature doesn't match this app; not moving to Applications")
                return false
            }
            // The user already chose to open it, and the copy is the same signed app; it shouldn't ask again.
            run("/usr/bin/xattr", ["-dr", "com.apple.quarantine", staged.path])
            if files.fileExists(atPath: destination.path) {
                try files.trashItem(at: destination, resultingItemURL: nil)
            }
            try files.moveItem(at: staged, to: destination)
        } catch {
            NSLog("Snowhush: could not move to Applications: \(error)")
            return false
        }
        let volume = (try? source.resourceValues(forKeys: [.volumeURLKey]))?.volume?.path ?? ""
        let script = """
        while /bin/kill -0 \(ProcessInfo.processInfo.processIdentifier) 2>/dev/null; do /bin/sleep 0.1; done
        for attempt in 1 2 3 4 5 6 7 8; do /usr/bin/hdiutil detach "$1" -quiet 2>/dev/null && break; /bin/sleep 0.5; done
        /usr/bin/open "$2"
        """
        run("/bin/sh", ["-c", script, "mover", volume, destination.path], wait: false)
        return true
    }

    /// Where the bundle really lives: macOS runs apps opened from a downloaded image from a randomized copy.
    private static func originalBundleURL() -> URL? {
        let url = Bundle.main.bundleURL
        typealias Original = @convention(c) (CFURL, UnsafeMutablePointer<Unmanaged<CFError>?>?) -> Unmanaged<CFURL>?
        guard url.path.contains("/AppTranslocation/"),
              let security = dlopen("/System/Library/Frameworks/Security.framework/Security", RTLD_LAZY),
              let symbol = dlsym(security, "SecTranslocateCreateOriginalPathForURL")
        else { return url }
        let original = unsafeBitCast(symbol, to: Original.self)
        return original(url as CFURL, nil)?.takeRetainedValue() as URL? ?? url
    }

    /// Whether the bundle at `url` is intact, nested code included, and meets this running app's own designated requirement.
    private static func isSignedLikeSelf(_ url: URL) -> Bool {
        var selfCode: SecCode?
        var selfStatic: SecStaticCode?
        var selfRequirement: SecRequirement?
        var copyStatic: SecStaticCode?
        guard SecCodeCopySelf([], &selfCode) == errSecSuccess, let running = selfCode,
              SecCodeCopyStaticCode(running, [], &selfStatic) == errSecSuccess, let own = selfStatic,
              SecCodeCopyDesignatedRequirement(own, [], &selfRequirement) == errSecSuccess, let requirement = selfRequirement,
              SecStaticCodeCreateWithPath(url as CFURL, [], &copyStatic) == errSecSuccess, let copy = copyStatic
        else { return false }
        let flags = SecCSFlags(rawValue: kSecCSCheckAllArchitectures | kSecCSCheckNestedCode | kSecCSStrictValidate)
        return SecStaticCodeCheckValidity(copy, flags, requirement) == errSecSuccess
    }

    private static func run(_ path: String, _ arguments: [String], wait: Bool = true) {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: path)
        process.arguments = arguments
        do {
            try process.run()
            if wait { process.waitUntilExit() }
        } catch {
            NSLog("Snowhush: \(path) failed: \(error)")
        }
    }
}
