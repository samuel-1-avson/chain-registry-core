/*
 * Supply Chain Malware Detection Rules for Chain Registry
 *
 * These YARA rules detect common supply-chain attack patterns in
 * npm, PyPI, crates.io, and other package ecosystem tarballs.
 *
 * Rules are organized by attack category. Each rule includes a
 * threat_level meta field (1-5) used for scoring.
 *
 * To add new rules: append to the appropriate section or create a
 * new file in rules/ — the scanner loads all .yar files in the directory.
 *
 * Reference: https://socket.dev/npm/issue (60+ categories)
 */

// ─── Data Exfiltration ──────────────────────────────────────────────────────

rule ExfilEnvVars : exfiltration {
    meta:
        description = "Collects and transmits environment variables (credential harvesting)"
        threat_level = 5
        category = "exfiltration"
    strings:
        $env1 = "process.env" nocase
        $env2 = "os.environ" nocase
        $env3 = "std::env::vars" nocase
        $env4 = "ENV.to_hash" nocase
        $send1 = "fetch(" nocase
        $send2 = "http.request" nocase
        $send3 = "requests.post" nocase
        $send4 = "XMLHttpRequest" nocase
        $send5 = "axios.post" nocase
        $send6 = "urllib.request" nocase
    condition:
        any of ($env*) and any of ($send*)
}

rule ExfilSSHKeys : exfiltration {
    meta:
        description = "Reads SSH keys and transmits them"
        threat_level = 5
        category = "exfiltration"
    strings:
        $ssh1 = ".ssh/id_rsa" nocase
        $ssh2 = ".ssh/id_ed25519" nocase
        $ssh3 = ".ssh/known_hosts" nocase
        $ssh4 = "BEGIN RSA PRIVATE KEY"
        $ssh5 = "BEGIN OPENSSH PRIVATE KEY"
        $send1 = "fetch(" nocase
        $send2 = "http" nocase
        $send3 = "request" nocase
    condition:
        any of ($ssh*) and any of ($send*)
}

rule ExfilBrowserData : exfiltration {
    meta:
        description = "Accesses browser credential stores"
        threat_level = 5
        category = "exfiltration"
    strings:
        $b1 = "Login Data" nocase
        $b2 = "Cookies" nocase
        $b3 = ".mozilla/firefox" nocase
        $b4 = "Chrome/User Data" nocase
        $b5 = "AppData\\Local\\Google" nocase
        $b6 = "keychain" nocase
    condition:
        2 of ($b*)
}

// ─── Obfuscation ────────────────────────────────────────────────────────────

rule HexEncodedPayload : obfuscation {
    meta:
        description = "Contains long hex-encoded strings likely hiding a payload"
        threat_level = 3
        category = "obfuscation"
    strings:
        $hex = /\\x[0-9a-f]{2}(\\x[0-9a-f]{2}){50,}/ nocase
    condition:
        $hex
}

rule Base64DecodedExec : obfuscation {
    meta:
        description = "Decodes base64 and executes the result"
        threat_level = 4
        category = "obfuscation"
    strings:
        $b64_1 = "atob(" nocase
        $b64_2 = "Buffer.from(" nocase
        $b64_3 = "base64.b64decode" nocase
        $b64_4 = "base64::decode" nocase
        $exec1 = "eval(" nocase
        $exec2 = "exec(" nocase
        $exec3 = "Function(" nocase
        $exec4 = "child_process" nocase
    condition:
        any of ($b64*) and any of ($exec*)
}

rule ObfuscatedStringConcat : obfuscation {
    meta:
        description = "Builds strings character-by-character to evade detection"
        threat_level = 3
        category = "obfuscation"
    strings:
        $c1 = /String\.fromCharCode\(\d+\)(,\s*String\.fromCharCode\(\d+\)){5,}/
        $c2 = /chr\(\d+\)\s*\.\s*chr\(\d+\)(\s*\.\s*chr\(\d+\)){5,}/
    condition:
        any of them
}

// ─── Remote Code Execution ──────────────────────────────────────────────────

rule InstallScriptShell : rce {
    meta:
        description = "Install scripts that spawn shell commands"
        threat_level = 4
        category = "install_script"
    strings:
        $pre = "preinstall" nocase
        $post = "postinstall" nocase
        $inst = "install" nocase
        $sh1 = "child_process" nocase
        $sh2 = "execSync" nocase
        $sh3 = "spawnSync" nocase
        $sh4 = "os.system" nocase
        $sh5 = "subprocess.run" nocase
        $sh6 = "subprocess.Popen" nocase
    condition:
        any of ($pre, $post, $inst) and any of ($sh*)
}

rule ReverseShell : rce {
    meta:
        description = "Reverse shell connection pattern"
        threat_level = 5
        category = "backdoor"
    strings:
        $rs1 = "/bin/sh" nocase
        $rs2 = "/bin/bash" nocase
        $rs3 = "cmd.exe" nocase
        $net1 = "net.Socket" nocase
        $net2 = "socket.socket" nocase
        $net3 = "TcpStream::connect" nocase
        $pipe = "pipe" nocase
    condition:
        any of ($rs*) and any of ($net*) and $pipe
}

rule CurlPipeShell : rce {
    meta:
        description = "Downloads and directly executes remote script (curl | sh)"
        threat_level = 5
        category = "dropper"
    strings:
        $c1 = "curl" nocase
        $c2 = "wget" nocase
        $c3 = "Invoke-WebRequest" nocase
        $pipe1 = "| sh" nocase
        $pipe2 = "| bash" nocase
        $pipe3 = "| python" nocase
        $pipe4 = "| node" nocase
        $pipe5 = "| powershell" nocase
    condition:
        any of ($c*) and any of ($pipe*)
}

// ─── Crypto Mining ──────────────────────────────────────────────────────────

rule CryptoMiner : cryptominer {
    meta:
        description = "Cryptocurrency mining indicators"
        threat_level = 5
        category = "cryptominer"
    strings:
        $m1 = "stratum+tcp://" nocase
        $m2 = "CryptoNight" nocase
        $m3 = "xmrig" nocase
        $m4 = "minergate" nocase
        $m5 = "coinhive" nocase
        $m6 = "cryptonight" nocase
        $m7 = "hashrate" nocase
        $pool = /[a-zA-Z0-9]{20,}\.[a-zA-Z0-9]{10,}:\d{4,5}/
    condition:
        2 of ($m*) or ($m1 and $pool)
}

// ─── Typosquatting & Dependency Confusion ───────────────────────────────────

rule SuspiciousPackageName : typosquat {
    meta:
        description = "Package name contains known typosquatting patterns"
        threat_level = 3
        category = "typosquat"
    strings:
        // Common typosquat prefixes/suffixes
        $t1 = "lodash-" nocase
        $t2 = "express-" nocase
        $t3 = "-js" nocase
        $t4 = "-node" nocase
        $t5 = "colors-" nocase
        $t6 = "request-" nocase
    condition:
        // Only flag in package.json name field context
        any of them
}

// ─── Network Backdoors ──────────────────────────────────────────────────────

rule HiddenHTTPServer : backdoor {
    meta:
        description = "Creates a hidden HTTP server for command and control"
        threat_level = 4
        category = "backdoor"
    strings:
        $s1 = "createServer" nocase
        $s2 = "http.Server" nocase
        $s3 = "listen(" nocase
        $s4 = "0.0.0.0" nocase
    condition:
        ($s1 or $s2) and $s3 and $s4
}

rule DNSExfiltration : exfiltration {
    meta:
        description = "Uses DNS queries to exfiltrate data"
        threat_level = 4
        category = "exfiltration"
    strings:
        $d1 = "dns.resolve" nocase
        $d2 = "dns.lookup" nocase
        $d3 = "Resolve-DnsName" nocase
        $d4 = "getaddrinfo" nocase
        $enc = /[a-zA-Z0-9+\/]{20,}\.[\w]+\.[\w]+/
    condition:
        any of ($d*) and $enc
}

// ─── Filesystem Tampering ───────────────────────────────────────────────────

rule WritesToSystemPaths : filesystem {
    meta:
        description = "Writes to system-critical paths"
        threat_level = 4
        category = "filesystem"
    strings:
        $w1 = "writeFileSync" nocase
        $w2 = "fs.writeFile" nocase
        $w3 = "open(" nocase
        $p1 = "/etc/passwd" nocase
        $p2 = "/etc/shadow" nocase
        $p3 = "/etc/crontab" nocase
        $p4 = "~/.bashrc" nocase
        $p5 = "~/.zshrc" nocase
        $p6 = "~/.profile" nocase
        $p7 = "/usr/local/bin" nocase
        $p8 = "AppData\\Roaming" nocase
    condition:
        any of ($w*) and any of ($p*)
}

rule CrontabPersistence : persistence {
    meta:
        description = "Installs crontab entries for persistence"
        threat_level = 5
        category = "persistence"
    strings:
        $c1 = "crontab" nocase
        $c2 = "/etc/cron" nocase
        $c3 = "schtasks" nocase
        $c4 = "Task Scheduler" nocase
    condition:
        any of them
}

// ─── Prototype Pollution (JS-specific) ──────────────────────────────────────

rule PrototypePollution : vulnerability {
    meta:
        description = "Prototype pollution gadget"
        threat_level = 3
        category = "vulnerability"
    strings:
        $pp1 = "__proto__" nocase
        $pp2 = "constructor.prototype" nocase
        $pp3 = "Object.assign" nocase
    condition:
        any of ($pp*)
}

// ─── Dependency Confusion ───────────────────────────────────────────────────

rule DependencyConfusionMarker : supply_chain {
    meta:
        description = "Dependency confusion attack indicator — package reaches out on install with internal hostname or metadata"
        threat_level = 4
        category = "supply_chain"
    strings:
        $dns1  = /https?:\/\/[a-z0-9\-]+\.burpcollaborator\.net/ nocase
        $dns2  = /https?:\/\/[a-z0-9\-]+\.interact\.sh/ nocase
        $dns3  = /https?:\/\/[a-z0-9\-]+\.oastify\.com/ nocase
        $dns4  = /https?:\/\/[a-z0-9\-]+\.canarytokens\.com/ nocase
        $ns    = "dns.resolve" nocase
        $host  = "os.hostname()" nocase
        $user  = "os.userInfo()" nocase
    condition:
        any of ($dns*) or ($ns and ($host or $user))
}

// ─── Install Hook Abuse ─────────────────────────────────────────────────────

rule InstallHookAbuse : supply_chain {
    meta:
        description = "Suspicious code execution in npm lifecycle hooks (preinstall/postinstall)"
        threat_level = 4
        category = "supply_chain"
    strings:
        $hook1 = "\"preinstall\"" nocase
        $hook2 = "\"postinstall\"" nocase
        $hook3 = "\"preuninstall\"" nocase
        $exec1 = "child_process" nocase
        $exec2 = "exec(" nocase
        $exec3 = "execSync(" nocase
        $exec4 = "spawn(" nocase
    condition:
        any of ($hook*) and any of ($exec*)
}

// ─── Shadowed Builtins ──────────────────────────────────────────────────────

rule ShadowedBuiltins : evasion {
    meta:
        description = "Overwriting built-in functions to intercept calls"
        threat_level = 3
        category = "evasion"
    strings:
        $s1 = /require\s*=\s*function/ nocase
        $s2 = /console\s*=\s*\{/ nocase
        $s3 = /JSON\.parse\s*=\s*function/ nocase
        $s4 = /JSON\.stringify\s*=\s*function/ nocase
        $s5 = /Buffer\s*=\s*function/ nocase
        $s6 = /process\.exit\s*=\s*function/ nocase
    condition:
        any of them
}

// ─── Credential Harvesting ──────────────────────────────────────────────────

rule CredentialHarvesting : exfiltration {
    meta:
        description = "Reads credential files or environment variables and sends them externally"
        threat_level = 5
        category = "exfiltration"
    strings:
        $cred1 = ".npmrc" nocase
        $cred2 = ".pypirc" nocase
        $cred3 = ".docker/config.json" nocase
        $cred4 = ".aws/credentials" nocase
        $cred5 = ".ssh/id_rsa" nocase
        $cred6 = ".gitconfig" nocase
        $cred7 = "NPM_TOKEN" nocase
        $cred8 = "GITHUB_TOKEN" nocase
        $send1 = "fetch(" nocase
        $send2 = "XMLHttpRequest" nocase
        $send3 = "http.request(" nocase
        $send4 = "https.request(" nocase
        $send5 = "requests.post(" nocase
    condition:
        2 of ($cred*) and any of ($send*)
}

// ─── Dynamic Require / Import ───────────────────────────────────────────────

rule DynamicRequire : evasion {
    meta:
        description = "Runtime-computed module loading to hide true dependencies"
        threat_level = 3
        category = "evasion"
    strings:
        $dr1 = /require\s*\(\s*[a-zA-Z_$]/ nocase
        $dr2 = /import\s*\(\s*[a-zA-Z_$]/ nocase
        $dr3 = /require\s*\(\s*Buffer\.from/ nocase
        $dr4 = /require\s*\(\s*atob\s*\(/ nocase
    condition:
        any of ($dr3, $dr4) or (#dr1 > 5) or (#dr2 > 5)
}

// ─── ReDoS — Malicious Regular Expressions ──────────────────────────────────

rule ReDoSPattern : vulnerability {
    meta:
        description = "Potentially catastrophic back-tracking regex (ReDoS)"
        threat_level = 2
        category = "vulnerability"
    strings:
        $re1 = /\([^)]*\+\)[^*]*\+/ nocase
        $re2 = /\(\.\*\)\+/ nocase
        $re3 = /\([^)]+\|[^)]+\)\{/ nocase
    condition:
        any of them
}

// ─── Typosquat Lookalike Names ──────────────────────────────────────────────

rule TyposquatIndicator : supply_chain {
    meta:
        description = "Package metadata contains names suspiciously similar to popular packages"
        threat_level = 3
        category = "supply_chain"
    strings:
        $t1 = "loadsh" nocase
        $t2 = "axois" nocase
        $t3 = "requets" nocase
        $t4 = "collors" nocase
        $t5 = "fkr" nocase
        $t6 = "cholk" nocase
        $t7 = "epress" nocase
        $t8 = "reeact" nocase
        $t9 = "lodashs" nocase
        $t10 = "momnet" nocase
    condition:
        any of them
}

// ─── Python setup.py Backdoor ───────────────────────────────────────────────

rule PythonSetupBackdoor : supply_chain {
    meta:
        description = "Suspicious code execution in setup.py install command override"
        threat_level = 5
        category = "supply_chain"
    strings:
        $setup    = "setup(" nocase
        $cmdclass = "cmdclass" nocase
        $install  = "install" nocase
        $exec1    = "os.system(" nocase
        $exec2    = "subprocess" nocase
        $exec3    = "exec(" nocase
        $exec4    = "compile(" nocase
    condition:
        $setup and $cmdclass and $install and any of ($exec*)
}

// ─── Encoded Payload Loader ─────────────────────────────────────────────────

rule EncodedPayloadLoader : obfuscation {
    meta:
        description = "Downloads and executes encoded payload from remote URL"
        threat_level = 5
        category = "obfuscation"
    strings:
        $fetch1 = "curl " nocase
        $fetch2 = "wget " nocase
        $fetch3 = "Invoke-WebRequest" nocase
        $fetch4 = "urllib.request" nocase
        $decode1 = "base64" nocase
        $decode2 = "atob(" nocase
        $exec1  = "eval(" nocase
        $exec2  = "exec(" nocase
        $exec3  = "| bash" nocase
        $exec4  = "| sh" nocase
        $exec5  = "| python" nocase
    condition:
        any of ($fetch*) and any of ($decode*) and any of ($exec*)
}

// ─── Dynamic / Obfuscated Property & Builtins Lookup ──────────────────────

rule DynamicPropertyLookup : obfuscation {
    meta:
        description = "Detects dynamic property lookup on global objects used to evade static analysis"
        threat_level = 4
        category = "obfuscation"
    strings:
        // Match things like globalThis['ev' + 'al'] or window["ev" + "al"]
        $lookup1 = /(globalThis|window|global|frames|self|parent|top)\[\s*['"][a-zA-Z0-9_\-\.\/]+['"]\s*(\+|\.concat\()\s*['"][a-zA-Z0-9_\-\.\/]+['"]/ nocase
        // Or using dynamic variables or concat on global
        $lookup2 = /(globalThis|window|global)\[\s*[^\]]+(\+|concat)[^\]]+\]/ nocase
    condition:
        any of them
}

rule PythonDynamicBuiltins : obfuscation {
    meta:
        description = "Detects Python dynamic builtin resolution to bypass static analysis"
        threat_level = 4
        category = "obfuscation"
    strings:
        $p1 = "getattr(__builtins__" nocase
        $p2 = "__builtins__.__dict__" nocase
        $p3 = "eval(compile(" nocase
    condition:
        any of them
}

