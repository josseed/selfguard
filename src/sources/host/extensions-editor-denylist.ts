/**
 * Public reports of malicious or compromised VS Code Marketplace / Open VSX extensions
 * (2025-2026): GlassWorm, fake Solidity extensions, the Nx Console 18.95.0 compromise. Only
 * ids with a public source are listed; the URL above each group is that source. Ids are
 * lower-case (matching is case-insensitive). A null `versions` denies every version; a list
 * denies only those releases (a compromised release of an otherwise legitimate extension).
 *
 * Not listed on purpose: the 72 "sleeper" extensions of Socket's April 2026 report (not
 * activated, so not confirmed malicious). Add an id only with a link a user can read.
 */
export interface DeniedExtension {
  versions: readonly string[] | null;
}

type Row = readonly [id: string, versions: readonly string[] | null];

const GROUPS: Row[][] = [
  // https://securitylabs.datadoghq.com/articles/mut-9332-malicious-solidity-vscode-extensions/
  [
    ["smartcontractai.solaibot", null],
    ["ethcompiler.among-eth", null],
    ["johngaffney.blankebesxstnion", null],
  ],
  // https://checkmarx.com/zero-post/solidity-devs-targeted-again-malicious-vs-code-extension-drops-screenconnect-based-remote-access-trojan-rat/
  [["juanblan281.solid281", null]],
  // https://thehackernews.com/2026/08/solidity-pro-vs-code-extensions-steal.html
  [
    ["helper-beeps.solidity-pro", null],
    ["web3devtoolsx.solidity-pro", null],
  ],
  // https://thehackernews.com/2025/10/self-spreading-glassworm-infects-vs.html (GlassWorm, first wave)
  [
    ["codejoy.codejoy-vscode-extension", ["1.8.3", "1.8.4"]],
    ["l-igh-t.vscode-theme-seti-folder", ["1.2.3"]],
    ["kleinesfilmroellchen.serenity-dsl-syntaxhighlight", ["0.3.2"]],
  ],
  // https://socket.dev/blog/glassworm-loader-hits-open-vsx-via-suspected-developer-account-compromise (GlassWorm, December 2025 cluster)
  [
    ["angular-studio.ng-angular-extension", null],
    ["awesome-codebase.codebase-dart-pro", null],
    ["cudra-production.vsce-prettier-pro", null],
    ["dev-studio-sense.php-comp-tools-vscode", null],
    ["ko-zu-gun-studio.synchronization-settings-vscode", null],
    ["littensy-studio.magical-icons", null],
    ["pretty-studio-advisor.prettyxml-formatter", null],
    ["sol-studio.solidity-extension", null],
    ["studio-jjalaire-team.professional-quarto-extension", null],
    ["studio-velte-distributor.pro-svelte-extension", null],
    ["sun-shine-studio.shiny-extension-for-vscode", null],
    ["tucyzirille-studio.angular-pro-tools-extension", null],
    ["vce-brendan-studio-eich.js-debuger-vscode", null],
  ],
  // https://socket.dev/blog/glassworm-loader-hits-open-vsx-via-suspected-developer-account-compromise (hijacked publisher, 30 January 2026)
  [
    ["oorzc.ssh-tools", ["0.5.1"]],
    ["oorzc.i18n-tools-plus", ["1.6.8"]],
    ["oorzc.mind-map", ["1.0.61"]],
    ["oorzc.scss-to-css-compile", ["1.3.4"]],
  ],
  // https://nx.dev/blog/nx-console-v18-95-0-postmortem and GHSA-c9j4-9m59-847w (CVE-2026-48027)
  [["nrwl.angular-console", ["18.95.0"]]],
  // https://socket.dev/blog/73-open-vsx-sleeper-extensions-glassworm (activated, April 2026)
  [
    ["outsidestormcommand.monochromator-theme", null],
    ["keyacrosslaud.auto-loop-for-antigravity", null],
    ["krundoven.ironplc-fast-hub", null],
    ["boulderzitunnel.vscode-buddies", null],
    ["cubedivervolt.html-code-validate", null],
    ["winnerdomain17.version-lens-tool", null],
    ["drobnyak.angular-auto-helper", null],
    ["galushko.vsclassic-auto-pilot", null],
    ["gusarev.mermaid-super-studio", null],
    ["lavrentev.project-live-studio", null],
    ["lesnitsky.tikbook-easy-lens", null],
    ["mashulin.vue-easy-studio", null],
    ["mitrokhin.vsc-easy-studio", null],
    ["mlechevik.nunjucks-rich-pilot", null],
    ["mokridin.material-pro-suite", null],
    ["ovchinin.markdown-live-craft", null],
    ["peschanov.dbcode-smart-suite", null],
    ["platarov.podmanager-pro-craft", null],
    ["polikash.pretty-deep-kit", null],
    ["porzhnev.swiftformat-deep-hub", null],
    ["smolyak.slog-smart-studio", null],
    ["svetelin.industrious-live-hub", null],
    ["tarasenya.todo-rich-hub", null],
  ],
];

/** Lower-case id -> what is denied. */
export const DENYLIST: ReadonlyMap<string, DeniedExtension> = new Map(GROUPS.flat().map(([id, versions]): [string, DeniedExtension] => [id, { versions }]));

/** Does this installed extension (id and version as written) match the list? */
export function deniedExtension(id: string, version: string): boolean {
  const entry = DENYLIST.get(id.toLowerCase());
  return !!entry && (entry.versions === null || entry.versions.includes(version));
}
