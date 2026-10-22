import { describe, expect, it } from "vitest";
import { encodePlist, parsePlist, parsePlistDict, PlistError, type PlistValue } from "./plist.js";

describe("plist codec", () => {
  it("round-trips the value types MDM uses", () => {
    const value: PlistValue = {
      MessageType: "Authenticate",
      UDID: "00008030-ABC",
      Count: 3,
      Ratio: 1.5,
      Supervised: true,
      Managed: false,
      When: new Date("2026-10-21T12:00:00Z"),
      Token: new Uint8Array([1, 2, 3, 4]),
      Profiles: ["a", "b"],
      Empty: {},
      Nested: { Inner: ["x"], Flag: true },
    };
    const xml = encodePlist(value);
    expect(xml).toContain('<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"');
    expect(parsePlist(xml)).toEqual(value);
  });

  it("escapes XML special characters in strings and keys", () => {
    const xml = encodePlist({ "a&b": "<tag> & \"quote\"" });
    expect(xml).toContain("<key>a&amp;b</key>");
    expect(parsePlistDict(xml)["a&b"]).toBe('<tag> & "quote"');
  });

  it("parses a real Apple check-in message", () => {
    const xml = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>MessageType</key><string>TokenUpdate</string>
  <key>Topic</key><string>com.apple.mgmt.External.abc</string>
  <key>UDID</key><string>00008030-001A2B3C</string>
  <key>PushMagic</key><string>MAGIC-1</string>
  <key>Token</key><data>AQIDBA==</data>
  <key>UnlockToken</key><data>BQYH</data>
</dict>
</plist>`;
    const d = parsePlistDict(xml);
    expect(d.MessageType).toBe("TokenUpdate");
    expect(d.UDID).toBe("00008030-001A2B3C");
    expect(d.Token).toEqual(new Uint8Array([1, 2, 3, 4]));
  });

  it("handles empty elements and self-closing tags", () => {
    const d = parsePlistDict("<plist><dict><key>s</key><string/><key>a</key><array/><key>d</key><dict/></dict></plist>");
    expect(d).toEqual({ s: "", a: [], d: {} });
  });

  it("rejects malformed input and unsupported elements", () => {
    expect(() => parsePlist("<plist><dict><key>x</key><set/></dict></plist>")).toThrow(PlistError);
    expect(() => parsePlist("not xml at all")).toThrow(PlistError);
    expect(() => parsePlistDict("<plist><array><string>x</string></array></plist>")).toThrow(/dictionary/);
  });
});
