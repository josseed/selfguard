// "Download for Mac" buttons: point straight at the DMG for this Mac's architecture, with a
// link to the other one. Release assets carry the version in their name
// (selfguard-0.18.1-arm64.dmg), so the latest ones come from the GitHub API. Until that answers,
// or if it can't, the buttons keep their href: the latest release page.

const API = "https://api.github.com/repos/josseed/selfguard/releases/latest";
const CACHE_KEY = "selfguard-latest-release";
const LABEL = { arm64: "Apple Silicon", x64: "Intel" };

async function latestRelease() {
  try {
    const cached = JSON.parse(sessionStorage.getItem(CACHE_KEY) || "null");
    if (cached && Date.now() - cached.at < 10 * 60 * 1000) return cached.release;
  } catch {}
  const res = await fetch(API, { headers: { Accept: "application/vnd.github+json" } });
  if (!res.ok) throw new Error(`GitHub API ${res.status}`);
  const data = await res.json();
  const dmg = (arch) => data.assets.find((a) => new RegExp(`-${arch}\\.dmg$`).test(a.name));
  const release = { version: data.tag_name.replace(/^v/, ""), arm64: null, x64: null };
  for (const arch of ["arm64", "x64"]) {
    const a = dmg(arch);
    if (a) release[arch] = { url: a.browser_download_url, mb: Math.round(a.size / 1e6) };
  }
  try { sessionStorage.setItem(CACHE_KEY, JSON.stringify({ at: Date.now(), release })); } catch {}
  return release;
}

const isMac = () => /Macintosh|Mac OS X/.test(navigator.userAgent) && !(navigator.maxTouchPoints > 1); // iPads claim to be Macs

/** "arm64", "x64", or null when the browser won't say. */
async function detectArch() {
  // Chrome and Edge tell us directly.
  try {
    const ua = await navigator.userAgentData?.getHighEntropyValues?.(["architecture"]);
    if (ua?.architecture === "arm") return "arm64";
    if (ua?.architecture === "x86") return "x64";
  } catch {}
  // Safari and Firefox always say "Intel Mac OS X"; the GPU name gives it away when exposed.
  try {
    const gl = document.createElement("canvas").getContext("webgl");
    const ext = gl?.getExtension("WEBGL_debug_renderer_info");
    const gpu = ext ? gl.getParameter(ext.UNMASKED_RENDERER_WEBGL) : "";
    if (/Apple M\d|Apple GPU/i.test(gpu) && !/Intel|AMD|Radeon/i.test(gpu)) return "arm64";
    if (/Intel|AMD|Radeon/i.test(gpu)) return "x64";
  } catch {}
  return null;
}

export async function setupDownloads() {
  const blocks = [...document.querySelectorAll("[data-download]")];
  if (!blocks.length) return;

  const [release, detected] = await Promise.all([latestRelease().catch(() => null), detectArch()]);
  if (!release || (!release.arm64 && !release.x64)) return; // keep the release-page links

  // Apple Silicon unless this Mac says otherwise: every Mac sold since 2020.
  let arch = detected || "arm64";
  if (!release[arch]) arch = arch === "arm64" ? "x64" : "arm64";
  const other = arch === "arm64" ? "x64" : "arm64";
  const sure = isMac() && detected === arch;

  for (const block of blocks) {
    const main = block.querySelector("[data-download-main]");
    const meta = block.querySelector("[data-download-meta]");
    const alt = block.querySelector("[data-download-alt]");
    main.href = release[arch].url;
    main.setAttribute("download", "");
    main.setAttribute("aria-label", `Download selfguard ${release.version} for Mac (${LABEL[arch]})`);
    if (meta) {
      meta.textContent = `${LABEL[arch]}${sure ? " (your Mac)" : ""} · v${release.version} · ${release[arch].mb} MB`;
    }
    if (alt && release[other]) {
      alt.href = release[other].url;
      alt.setAttribute("download", "");
      alt.textContent = other === "x64" ? "Intel Mac? Download for Intel" : "Apple Silicon? Download for M-series";
      alt.hidden = false;
    }
  }
}
