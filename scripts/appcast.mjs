#!/usr/bin/env node
// Write the Sparkle appcast of one architecture for a release, from its notarized DMG:
//
//   node scripts/appcast.mjs <dmg> <arch> <edSignature> <length>   → macos/build/appcast-<arch>.xml
//
// The release workflow then signs the feed itself (sign_update embeds the signature; the app
// requires it, SURequireSignedFeed) and attaches it to the release. The app reads it from
// releases/latest/download/appcast-<arch>.xml (scripts/build-app.sh). The release notes come
// from this version's CHANGELOG section, rendered as plain HTML (text escaped first).
import { readFileSync, writeFileSync } from "node:fs";
import { basename } from "node:path";

const [dmg, arch, signature, length] = process.argv.slice(2);
if (!dmg || !["arm64", "x64"].includes(arch) || !/^[A-Za-z0-9+/]+={0,2}$/.test(signature ?? "") || !/^\d+$/.test(length ?? "")) {
  console.error("usage: node scripts/appcast.mjs <dmg> <arm64|x64> <edSignature> <length>");
  process.exit(2);
}
const root = new URL("../", import.meta.url);
const version = JSON.parse(readFileSync(new URL("package.json", root), "utf8")).version;
if (!/^\d+\.\d+\.\d+$/.test(version)) throw new Error(`unexpected version ${version}`);
const name = basename(dmg);
if (name !== `selfguard-${version}-${arch}.dmg`) throw new Error(`${name} isn't the DMG of ${version} (${arch})`);

const REPO = "https://github.com/josseed/selfguard";
const esc = (s) => s.replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;").replaceAll('"', "&quot;");

/** This version's CHANGELOG section as HTML: headings, bullets, bold, code and links. */
function notes() {
  const text = readFileSync(new URL("CHANGELOG.md", root), "utf8");
  const start = text.indexOf(`## [${version}]`);
  if (start < 0) return `<p><a href="${REPO}/releases/tag/v${version}">What's new in ${version}</a></p>`;
  const end = text.indexOf("\n## [", start + 1);
  const section = text.slice(text.indexOf("\n", start) + 1, end < 0 ? undefined : end);
  const inline = (s) =>
    esc(s)
      .replace(/\*\*(.+?)\*\*/g, "<strong>$1</strong>")
      .replace(/`([^`]+)`/g, "<code>$1</code>")
      .replace(/\[([^\]]+)\]\((https:\/\/[^)\s]+|[\w./-]+)\)/g, (_, label, href) =>
        `<a href="${href.startsWith("https://") ? href : `${REPO}/blob/v${version}/${href}`}">${label}</a>`);
  const html = [];
  let item = null;
  const flush = () => {
    if (item !== null) html.push(`<li>${inline(item)}</li>`);
    item = null;
  };
  let inList = false;
  for (const line of section.split("\n")) {
    if (/^- /.test(line)) {
      flush();
      if (!inList) html.push("<ul>");
      inList = true;
      item = line.slice(2);
    } else if (/^\s{2,}\S/.test(line) && item !== null) {
      item += ` ${line.trim()}`;
    } else {
      flush();
      if (inList && line.trim() !== "") {
        html.push("</ul>");
        inList = false;
      }
      if (/^### /.test(line)) html.push(`<h3>${inline(line.slice(4))}</h3>`);
      else if (line.trim()) html.push(`<p>${inline(line)}</p>`);
    }
  }
  flush();
  if (inList) html.push("</ul>");
  return html.join("\n");
}

const xml = `<?xml version="1.0" encoding="utf-8"?>
<rss version="2.0" xmlns:sparkle="http://www.andymatuschak.org/xml-namespaces/sparkle">
  <channel>
    <title>selfguard</title>
    <link>${REPO}</link>
    <item>
      <title>selfguard ${version}</title>
      <pubDate>${new Date().toUTCString()}</pubDate>
      <sparkle:version>${version}</sparkle:version>
      <sparkle:shortVersionString>${version}</sparkle:shortVersionString>
      <sparkle:minimumSystemVersion>13.0</sparkle:minimumSystemVersion>${arch === "arm64" ? "\n      <sparkle:hardwareRequirements>arm64</sparkle:hardwareRequirements>" : ""}
      <sparkle:fullReleaseNotesLink>${REPO}/releases/tag/v${version}</sparkle:fullReleaseNotesLink>
      <description><![CDATA[${notes().replaceAll("]]>", "]]&gt;")}]]></description>
      <enclosure url="${REPO}/releases/download/v${version}/${name}" length="${length}" type="application/octet-stream" sparkle:edSignature="${signature}"/>
    </item>
  </channel>
</rss>
`;
const out = new URL(`macos/build/appcast-${arch}.xml`, root);
writeFileSync(out, xml);
console.log(`wrote ${out.pathname}`);
