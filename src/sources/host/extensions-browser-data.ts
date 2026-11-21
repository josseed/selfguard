/**
 * Browser extensions publicly reported as malicious or hijacked (Chrome Web Store IDs). Data
 * only; every entry names its public source (SOURCES holds the URL of each report). `versions`
 * set: only those releases were malicious (a hijacked, since-repaired extension): any other
 * version doesn't match. Without `versions` the whole extension is malicious. Only add IDs a
 * public report lists.
 */
export interface DeniedExtension {
  name: string;
  src: keyof typeof SOURCES;
  versions?: string[];
}

export const SOURCES = {
  // Dec 2024 Cyberhaven campaign: developer phishing, trojanized updates (table with versions).
  rhisac: "https://rhisac.org/threat-intelligence/cyberhaven-extension-compromise-part-of-broader-campaign-affecting-multiple-chrome-extensions/",
  cyberhaven: "https://www.cyberhaven.com/engineering-blog/cyberhavens-preliminary-analysis-of-the-recent-malicious-chrome-extension",
  // Dec 2025: leaked Chrome Web Store API key used to publish a wallet-draining 2.68.
  trustwallet: "https://trustwallet.com/blog/company/trust-wallet-browser-extension-v268-incident-community-update",
  // 2025 Socket report on crypto/wallet stealers, as listed by BleepingComputer.
  socket: "https://www.bleepingcomputer.com/news/security/chrome-web-store-extensions-caught-stealing-crypto-browser-data/",
  // 2025 LayerX / Akamai campaign of 40+ fake VPN, AI, crypto and ad-spy extensions.
  layerx: "https://www.akamai.com/blog/security/layerx-reveals-40malicious-browser-extensions",
  // 2025 DomainTools: dual-function malware in Chrome extensions.
  domaintools: "https://dti.domaintools.com/research/hidden-threats-of-dual-function-malware-found-in-chrome-extensions",
  // 2026 Unit 42: fake "Chrome MCP Server" extension (affiliate hijacking and data exfiltration).
  unit42: "https://unit42.paloaltonetworks.com/high-risk-gen-ai-browser-extensions/",
} as const;

const R = "rhisac";
const L = "layerx";
const S = "socket";

export const DENYLIST: Record<string, DeniedExtension> = {
  // --- Cyberhaven and the December 2024 campaign (hijacked: only the listed versions) ---
  pajkjnmeojmbapicmbpliphjmcekeaac: { name: "Cyberhaven", src: "cyberhaven", versions: ["24.10.4"] },
  nnpnnpemnckcfdebeekibpiijlicmpom: { name: "VPNCity", src: R, versions: ["2.0.1"] },
  kkodiihpgodmdankclfibbiphjkfdenh: { name: "Parrot Talks", src: R, versions: ["1.16.2"] },
  oaikpkmjciadfpddlpjjdapglcihgdle: { name: "Uvoice", src: R, versions: ["1.0.12"] },
  dpggmcodlahmljkhlmpgpdcffdaoccni: { name: "Internxt VPN", src: R, versions: ["1.1.1"] },
  acmfnomgphggonodopogfbmkneepfgnh: { name: "Bookmark Favicon Changer", src: R, versions: ["4.00"] },
  mnhffkhmpnefgklngfmlndmkimimbphc: { name: "Castorus", src: R, versions: ["4.40"] },
  cedgndijpacnfbdggppddacngjfdkaca: { name: "Wayin AI", src: R, versions: ["0.0.11"] },
  bbdnohkpnbkdkmnkddobeafboooinpla: { name: "Search Copilot AI Assistant for Chrome", src: R, versions: ["1.0.1"] },
  egmennebgadmncfjafcemlecimkepcle: { name: "VidHelper", src: R, versions: ["2.2.7"] },
  bibjgkidgpfbblifamdlkdlhgihmfohh: { name: "AI Assistant - ChatGPT and Gemini for Chrome", src: R, versions: ["0.1.3"] },
  cplhlgabfijoiabgkigdafklbhhdkahj: { name: "Vidnoz Flex", src: R, versions: ["1.0.161"] },
  befflofjcniongenjmbkgkoljhgliihe: { name: "TinaMind", src: R, versions: ["2.13.0"] },
  pkgciiiancapdlpcbppfkmeaieppikkk: { name: "Bard AI chat", src: R, versions: ["1.3.7"] },
  llimhhconnjiflfimocjggfjdlmlhblm: { name: "Reader Mode", src: R, versions: ["1.5.7"] },
  oeiomhmbaapihbilkfkhmlajkeegnjhe: { name: "Primus (prev. PADO)", src: R, versions: ["3.18.0"] },
  ekpkdmohpdnebfedjjfklhpefgpgaaji: { name: "Tackker", src: R, versions: ["1.3"] },
  epikoohpebngmakjinphfiagogjcnddm: { name: "AI Shop Buddy", src: R, versions: ["2.7.3", "2.7.5"] },
  miglaibdlgminlepgeifekifakochlka: { name: "Sort by Oldest", src: R, versions: ["1.4.5"] },
  eanofdhdfbcalhflpbdipkjjkoimeeod: { name: "Rewards Search Automator", src: R, versions: ["1.4.9"] },
  ogbhbgkiojdollpjbhbamafmedkeockb: { name: "Earny", src: R, versions: ["1.8.1"] },
  bgejafhieobnfpjlpcjjggoboebonfcg: { name: "ChatGPT Assistant - Smart Search", src: R, versions: ["1.1.1"] },
  igbodamhgjohafcenbcljfegbipdfjpk: { name: "Keyboard History Recorder", src: R, versions: ["2.3"] },
  mbindhfolmpijhodmgkloeeppmkhpmhc: { name: "Email Hunter", src: R, versions: ["1.4.4"] },
  hodiladlefdpcbemnbbcpclbmknkiaem: { name: "Visual Effects for Google Meet", src: R, versions: ["3.1.3"] },
  epdjhgbipjpbbhoccdeipghoihibnfja: { name: "GPT 4 Summary with OpenAI", src: R, versions: ["1.4"] },
  ndlbedplllcgconngcnfmkadhokfaaln: { name: "GraphQL Network Inspector", src: R, versions: ["2.22.6"] },
  jiofmdifioeejeilfkpegipdjiopiekl: { name: "YesCaptcha assistant", src: R, versions: ["1.1.61"] },
  hihblcmlaaademjlakdpicchbjnnnkbo: { name: "Proxy SwitchyOmega (V3)", src: R, versions: ["3.0.2"] },
  // --- Trust Wallet, December 2025 (hijacked: version 2.68 only) ---
  egjidjbpglichdcondbcbdnbeeppgdph: { name: "Trust Wallet", src: "trustwallet", versions: ["2.68"] },
  // --- Crypto and wallet stealers (Socket, 2025): malicious in every version ---
  pkoccklolohdacbfooifnpebakpbeipc: { name: "Enable Right Click & Copy", src: S },
  fegckejpfnlmfgkfjpinlbgmeeijjkel: { name: "RapidLens - Google Lens for Screen Search", src: S },
  kdenlnncndfnhkognokgfpabgkgehodd: { name: "QuickLens - Search Screen with Google Lens", src: S },
  jamminefolhgepgihbmcjjhgldbfcikp: { name: "Password Protect PDF", src: S },
  inmkjedjdhgpknjogbjomhnbgdccckkg: { name: "Allow Copy - Select & Enable Right Click", src: S },
  fcgdejjichpgfaaafflplhfijcnieopb: { name: "PixelCheck", src: S },
  cfpnjdbpojpcongfaefcamjbaolpelcd: { name: "Creative Library - Ad Spy Tool", src: S },
  aapdalkmclfaahehnmicbglkohkldhne: { name: "Website Traffic Checker: MirrorSphere", src: S },
  dkdadldmiefjldmegbjbnhhfddnkhlhm: { name: "Site Signal", src: S },
  fjmlhlkccegopebcllcmafahkmeejpph: { name: "SEO Pulse Pro", src: S },
  iekoapohahgmogbagegmcgplbkikcgke: { name: "Private Crypto News Reader", src: S },
  ahpnnnjbnfbhoikhohglpohnoocjcoco: { name: "Blockfolio: Address Monitor", src: S },
  oeacadlaclegkkkdehjmiifnjhcekclj: { name: "Crypto Rates & Fiat Converter", src: S },
  jmlgannjlbliikgcaieomgmcnfplglea: { name: "Crypto Alerter", src: S },
  lhmcajhgadanidbopgaoobjlldegjmke: { name: "DeFi Pulse Tracker", src: S },
  gfackggoapepdmnjnkblogdcjpgcjiak: { name: "Crypto Price Badge", src: S },
  hfijkbdkpidafdbeebnnkhfccildbcle: { name: "Multi-Chain Explorer", src: S },
  pcngchfbfgejllcbhmeadjhiebebiome: { name: "LedgerLook: Wallet Checker", src: S },
  aodkjdeghbjiaienipfjkbpcikkacbcp: { name: "Meta & Facebook Ad Library Spy", src: S },
  // --- Fake VPN, AI, crypto and ad-spy extensions (LayerX / Akamai, 2025) ---
  ccollcihnnpcbjcgcjfmabegkpbehnip: { name: "FortiVPN", src: L },
  aeibljandkelbcaaemkdnbaacppjdmom: { name: "Manus AI | Free AI Assistant", src: L },
  fcfmhlijjmckglejcgdclfneafoehafm: { name: "Site Stats", src: L },
  abbngaojehjekanfdipifimgmppiojpl: { name: "Clothing Brand Name Generator", src: L },
  dohmiglipinohflhapdagfgbldhmoojl: { name: "DeBank - Digital Assets", src: L },
  acmiibcdcmaghndcahglamnhnlmcmlng: { name: "AML Sector", src: L },
  mipophmjfhpecleajkijfifmffcjdiac: { name: "Crypto Whales Vision", src: L },
  cknmibbkfbephciofemdjndbgebggnkc: { name: "Calendly Daily", src: L },
  gmigkpkjegnpmjpmnmgnkhmoinpgdnfc: { name: "Calendly Docket", src: L },
  ahgccenjociolkbpgbfibmfclcfnlaei: { name: "CreativeHunter", src: L },
  kjhjnbdjonamibpaalanflmidplhiehe: { name: "Twin Web", src: L },
  pobknfocgoijjmokmhimkfhemcnigdji: { name: "EventSphere", src: L },
  iclckldkfemlnecocpphinnplnmijkol: { name: "SQLite browser", src: L },
  ihdnbohcfnegemgomjcpckmpnkdgopon: { name: "AI Sentence Rewriter", src: L },
  oeefjlikahigmlnplgijgeeecbpemhip: { name: "Convert PDF to JPG", src: L },
  aofddmgnidinflambjlfkpboeamdldbd: { name: "HTML validator", src: L },
  acchdggcflgidjdcnhnnkfengdcmldae: { name: "CMS Checker", src: L },
  albakpncdngcejcjdahomfbkakbmafgb: { name: "Hourly to salary calculator", src: L },
  hhlcpmdhlcoghhfgiiopcjbkfmdliknc: { name: "CSS validator", src: L },
  eheagnmidghfknkcaehacggccfiidhik: { name: "Email checker", src: L },
  ckcfkaikieiicfdeomgehmnjglnofhde: { name: "Crypto Whale Alert", src: L },
  pbpobpjppnecgcinajfpaninmjkdbidm: { name: "Web Analytics", src: L },
  gdfjahfbaillhkeigeinoomhjnfajbon: { name: "Ad Vision", src: L },
  eoalbaojjblgndkffciljmiddhgjdldh: { name: "Madgicx Plus", src: L },
  odhmhkkhpibfjijmpgcdjondompgocog: { name: "Similar Net", src: L },
  ohhhngpnknpdhmdmpmoccgjmmkkleipn: { name: "Meta Spy", src: L },
  nejfdccopmpimplhmmdfjobodgeaoihd: { name: "Free VPN - Raccoon", src: L },
  dhhmopcmpiadcgchhhldcpoeppcofdic: { name: "Free VPN - Orchid", src: L },
  ffmfnniephcagojkpjddjiogjeoijjgl: { name: "VPN Free - Soul VPN", src: L },
  nabbdpjneieneepdfnmkdhooellilgho: { name: "Website monitoring", src: L },
  mldeggofnfaiinachdeidpecmflffoam: { name: "AI Writer", src: L },
  pndmbpnfolikhfnfnkmjkkpcgkmaibec: { name: "AI Ad Generator", src: L },
  elipckbifniceedgalakgnmgeimfdcdi: { name: "Headline Generator", src: L },
  kkgmdjjpobmenpkhcclceelekpbnnana: { name: "Web Watch", src: L },
  dcnjgfafcnopabhpgoekkgckgkkddpjg: { name: "Youtube Vision", src: L },
  mllkmmdaapekjehapekhjjiednchgmag: { name: "Web Metrics", src: L },
  bhahpmoebdipfoaadcclkcnieeokebnf: { name: "Bitcoin price live", src: L },
  oliiideaalkijolilhhaibhbjfhbdcnm: { name: "Link shortener", src: L },
  // --- DomainTools (2025) ---
  pocfdebmmcmfanifcfeeiafokecfkikj: { name: "(unnamed in the report)", src: "domaintools" },
  // --- Unit 42 (2026): impostor of the Chrome MCP server ---
  fpeabamapgecnidibdmjoepaiehokgda: { name: "Chrome MCP Server - AI Browser Control", src: "unit42" },
};
