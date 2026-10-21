import AppKit

final class AppDelegate: NSObject, NSApplicationDelegate {
    var window: NSWindow!
    var input: NSTextField!
    var asText: NSButton!
    var log: NSTextView!
    var writeBtn: NSButton!
    var readBtn: NSButton!

    func applicationDidFinishLaunching(_ n: Notification) {
        let w = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 560, height: 460),
                         styleMask: [.titled, .closable, .miniaturizable],
                         backing: .buffered, defer: false)
        w.title = "AmigoTap NFC"
        w.center()
        window = w
        let v = NSView(frame: w.contentView!.bounds)
        v.autoresizingMask = [.width, .height]

        func label(_ s: String, _ y: CGFloat, _ size: CGFloat = 13, bold: Bool = false) -> NSTextField {
            let l = NSTextField(labelWithString: s)
            l.frame = NSRect(x: 20, y: y, width: 520, height: 20)
            l.font = bold ? NSFont.boldSystemFont(ofSize: size) : NSFont.systemFont(ofSize: size)
            v.addSubview(l); return l
        }

        _ = label("AmigoTap NFC", 420, 20, bold: true)
        _ = label("Place a tag or coin (MIFARE Classic or NTAG213/215/216) on the ACR122U, then choose an action.", 396, 11)
        _ = label("Link or text:", 362)

        input = NSTextField(frame: NSRect(x: 20, y: 332, width: 520, height: 24))
        input.stringValue = "https://linktree-flax-chi.vercel.app/mobile-space"
        input.placeholderString = "https://example.com/..."
        v.addSubview(input)

        asText = NSButton(checkboxWithTitle: "Write as plain text (instead of a URL link)",
                          target: nil, action: nil)
        asText.frame = NSRect(x: 20, y: 304, width: 520, height: 20)
        v.addSubview(asText)

        writeBtn = NSButton(title: "Write to Tag", target: self, action: #selector(doWrite))
        writeBtn.frame = NSRect(x: 20, y: 262, width: 140, height: 32)
        writeBtn.bezelStyle = .rounded
        writeBtn.keyEquivalent = "\r"
        v.addSubview(writeBtn)

        readBtn = NSButton(title: "Read Tag", target: self, action: #selector(doRead))
        readBtn.frame = NSRect(x: 168, y: 262, width: 120, height: 32)
        readBtn.bezelStyle = .rounded
        v.addSubview(readBtn)

        let scroll = NSScrollView(frame: NSRect(x: 20, y: 20, width: 520, height: 228))
        scroll.hasVerticalScroller = true
        scroll.borderType = .bezelBorder
        log = NSTextView(frame: scroll.bounds)
        log.isEditable = false
        log.font = NSFont.monospacedSystemFont(ofSize: 12, weight: .regular)
        log.autoresizingMask = [.width]
        scroll.documentView = log
        v.addSubview(scroll)

        w.contentView = v
        w.makeKeyAndOrderFront(nil)
        setStatus("Ready. Place a tag on the reader.\n")
        buildMenu()
    }

    func setStatus(_ s: String) { log.string = s }

    func run(_ action: @escaping (UnsafeMutablePointer<CChar>, Int32) -> Int32, verb: String) {
        writeBtn.isEnabled = false; readBtn.isEnabled = false
        setStatus("\(verb)...\n")
        DispatchQueue.global().async {
            let cap = 16384
            let buf = UnsafeMutablePointer<CChar>.allocate(capacity: cap)
            defer { buf.deallocate() }
            _ = action(buf, Int32(cap))
            let out = String(cString: buf)
            DispatchQueue.main.async {
                self.log.string = out
                self.writeBtn.isEnabled = true; self.readBtn.isEnabled = true
            }
        }
    }

    @objc func doWrite() {
        let val = input.stringValue
        let text: Int32 = (asText.state == .on) ? 1 : 0
        run({ buf, cap in val.withCString { amigo_write($0, text, buf, cap) } }, verb: "Writing")
    }

    @objc func doRead() {
        run({ buf, cap in amigo_read(buf, cap) }, verb: "Reading")
    }

    func buildMenu() {
        let main = NSMenu()
        let appItem = NSMenuItem()
        main.addItem(appItem)
        let appMenu = NSMenu()
        appMenu.addItem(withTitle: "Quit AmigoTap NFC", action: #selector(NSApplication.terminate(_:)), keyEquivalent: "q")
        appItem.submenu = appMenu
        NSApplication.shared.mainMenu = main
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ s: NSApplication) -> Bool { true }
}

let app = NSApplication.shared
let delegate = AppDelegate()
app.delegate = delegate
app.setActivationPolicy(.regular)
app.activate(ignoringOtherApps: true)
app.run()
