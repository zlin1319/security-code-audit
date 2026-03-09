#!/usr/bin/env python3
"""
Language patterns and rule metadata for the security audit tool.
"""

from typing import Dict, List, Tuple

SUPPORTED_LANGUAGES = [
    "java",
    "javascript",
    "typescript",
    "python",
    "php",
    "csharp",
    "kotlin",
    "go",
    "other",
]


RULE_DEFINITIONS: List[Tuple[str, str, str, str]] = [
    ("sqli-001", "CWE-89", "SQL Injection", "critical"),
    ("xss-001", "CWE-79", "Reflected Cross-Site Scripting", "high"),
    ("cmdi-001", "CWE-78", "Command Injection", "critical"),
    ("pathtraversal-001", "CWE-22", "Path Traversal", "high"),
    ("deserialization-001", "CWE-502", "Insecure Deserialization", "critical"),
    ("ssrf-001", "CWE-918", "Server-Side Request Forgery", "high"),
    ("crypto-001", "CWE-328", "Weak Hashing Algorithm", "high"),
    ("crypto-002", "CWE-327", "Weak Encryption Algorithm", "high"),
    ("crypto-003", "CWE-330", "Insecure Randomness", "medium"),
    ("infoleak-001", "CWE-200", "Sensitive Information Exposure", "medium"),
]


def get_language_patterns() -> Dict[str, Dict[str, str]]:
    java_patterns = {
        "sqli-001": r"String\s+\w+\s*=\s*\"[^\"]*SELECT[^\"]*\"\s*\+|\.executeQuery\s*\(",
        "xss-001": r"response\.getWriter\(\)\.(write|print)\s*\(\s*\"[^\"]*\<",
        "cmdi-001": r"(Runtime\.getRuntime\(\)\.exec|new\s+ProcessBuilder)\s*\(\s*\"[^\"]*\"\s*\+",
        "pathtraversal-001": r"new\s+(File|FileInputStream|Paths?)\s*\(\s*\"[^\"]*\"\s*\+",
        "deserialization-001": r"ObjectInputStream.*readObject",
        "ssrf-001": r"new\s+URL\s*\(\s*\w+\s*\)",
        "crypto-001": r"MessageDigest\.getInstance\s*\(\s*\"(MD5|SHA1|SHA-1)\"",
        "crypto-002": r"Cipher\.getInstance\s*\(\s*\"(?:DES|DESede|3DES|RC4|AES/ECB|DES/ECB|DESede/ECB)[^\"]*\"",
        "crypto-003": r"Random\s+\w+\s*=\s*new\s+Random\s*\(\)",
        "infoleak-001": r"(API_KEY|PASSWORD|SECRET|TOKEN)\s*=\s*\"[^\"]+\"|printStackTrace\s*\(\)",
    }

    js_patterns = {
        "sqli-001": r"(query|execute)\s*\(\s*.*[\+`]|query\s*\(\s*.*\+",
        "xss-001": r"(innerHTML|outerHTML|document\.write)\s*=\s*.*(?:req|param|input)|dangerouslySetInnerHTML",
        "cmdi-001": r"(exec|execSync)\s*\(\s*.*[\+`]|exec\s*\(\s*.*\+",
        "pathtraversal-001": r"(fs\.readFile|fs\.createReadStream)\s*\(\s*.*(?:req|param|input)",
        "deserialization-001": r"(serialize\.unserialize|eval)\s*\(\s*.*(?:req|param|input)",
        "ssrf-001": r"(fetch|axios\.(get|post)|request)\s*\(\s*.*(?:req|param|input)",
        "crypto-001": r"(crypto\.createHash\s*\(\s*[\'\"](md5|sha1)[\'\"]|bcrypt.*\d{1,2}\))",
        "crypto-002": r"(createCipher|createCipheriv)\s*\(\s*[\'\"](?:des|des-ede3|rc4)[\'\"]|aes-\d+-ecb",
        "infoleak-001": r"(password|secret|key|token)\s*=\s*[\'\"][^\'\"]+[\'\"]|console\.log\s*\(\s*.*error",
    }

    py_patterns = {
        "sqli-001": r"(cursor\.execute|connection\.execute)\s*\(\s*f?[\"'].*SELECT|f[\"'].*\{.*\}",
        "xss-001": r"(render_template_string|mark_safe|\.format\s*\(.*request)",
        "cmdi-001": r"(os\.system|subprocess\.call|subprocess\.run|Popen)\s*\(\s*.*(?:shell\s*=\s*True)",
        "pathtraversal-001": r"open\s*\(\s*.*(?:request|param)|Path\s*\(\s*.*request",
        "deserialization-001": r"pickle\.loads|yaml\.load\s*\(|json\.loads\s*\(\s*.*(?:request|param)",
        "ssrf-001": r"(requests\.(get|post)|urllib\.request\.urlopen)\s*\(\s*.*(?:request|param)",
        "crypto-001": r"(hashlib\.md5|hashlib\.sha1|\.encode\(\)|without\s*salt)",
        "crypto-002": r"(DES|ARC4|Blowfish)\.new\s*\(|modes\.ECB\s*\(",
        "crypto-003": r"random\.(random|randint|choice)|Random\s*\(\)",
        "infoleak-001": r"(password|secret|key|token)\s*=\s*[\"'][^\"']+[\"']|print\s*\(\s*.*exception",
    }

    php_patterns = {
        "sqli-001": r"(\$_(GET|POST|REQUEST)\[[^\]]+\].*(SELECT|INSERT|UPDATE|DELETE)|\"[^\"]*(SELECT|INSERT|UPDATE|DELETE)[^\"]*\"\s*\.\s*\$_(GET|POST|REQUEST)\[)",
        "xss-001": r"(echo|print)\s*[\"'][^\"']*<[^\"']*[\"']\s*\.\s*\$_(GET|POST|REQUEST)\[",
        "cmdi-001": r"(system|exec|shell_exec|passthru)\s*\(\s*\$_(GET|POST|REQUEST)\[",
        "pathtraversal-001": r"(file_get_contents|fopen|readfile|include|require)(_once)?\s*\(\s*\$_(GET|POST|REQUEST)\[",
        "deserialization-001": r"unserialize\s*\(\s*\$_(GET|POST|REQUEST)\[",
        "ssrf-001": r"(file_get_contents|curl_init)\s*\(\s*\$_(GET|POST|REQUEST)\[",
        "crypto-001": r"\b(md5|sha1)\s*\(",
        "crypto-002": r"(openssl_encrypt|mcrypt_[a-z_]+)\s*\(.*(des|des-ede3|rc4)",
        "crypto-003": r"\b(mt_rand|rand)\s*\(",
        "infoleak-001": r"(\$(password|secret|key|token)\s*=+\s*[\"'][^\"']+[\"']|var_dump\s*\(\s*\$e|echo\s+\$e->getMessage\s*\()",
    }

    csharp_patterns = {
        "sqli-001": r"\"[^\"]*(SELECT|INSERT|UPDATE|DELETE)[^\"]*\"\s*\+\s*\w+|SqlCommand\s*\(\s*\"[^\"]*(SELECT|INSERT|UPDATE|DELETE)[^\"]*\"\s*\+",
        "xss-001": r"Response\.Write\s*\(\s*\"[^\"]*<[^\"\n]*\"\s*\+\s*\w+",
        "cmdi-001": r"Process\.Start\s*\(\s*\"cmd(\.exe)?\"\s*,\s*\w+",
        "pathtraversal-001": r"(File|Directory)\.(Open|ReadAllText|ReadAllBytes|Delete)\s*\(\s*\w+",
        "deserialization-001": r"(BinaryFormatter|SoapFormatter|NetDataContractSerializer).*(Deserialize)\s*\(",
        "ssrf-001": r"(HttpClient|WebClient).*(GetStringAsync|DownloadString|OpenRead)\s*\(\s*\w+",
        "crypto-001": r"\b(MD5|SHA1)\.(Create|Managed)\s*\(",
        "crypto-002": r"CipherMode\.ECB|DES\.Create\s*\(|RC2\.Create\s*\(",
        "crypto-003": r"new\s+Random\s*\(\s*\)",
        "infoleak-001": r"(password|secret|key|token)\s*=\s*\"[^\"]+\"|Console\.WriteLine\s*\(\s*ex(\.Message)?",
    }

    kotlin_patterns = {
        "sqli-001": r"val\s+\w+\s*=\s*\"[^\"]*(SELECT|INSERT|UPDATE|DELETE)[^\"]*\"\s*\+\s*\w+",
        "xss-001": r"response\.writer\.(write|print)\s*\(\s*\"[^\"]*<[^\"\n]*\"\s*\+\s*\w+",
        "cmdi-001": r"(Runtime\.getRuntime\(\)\.exec|ProcessBuilder)\s*\(\s*\"[^\"]*\"\s*\+\s*\w+|ProcessBuilder\s*\(\s*\"sh\"\s*,\s*\"-c\"\s*,\s*\w+",
        "pathtraversal-001": r"(File|Paths\.get)\s*\(\s*\w+\s*\)",
        "deserialization-001": r"ObjectInputStream.*readObject",
        "ssrf-001": r"URL\s*\(\s*\w+\s*\)\.openConnection\s*\(",
        "crypto-001": r"MessageDigest\.getInstance\s*\(\s*\"(MD5|SHA1|SHA-1)\"",
        "crypto-002": r"Cipher\.getInstance\s*\(\s*\"(?:DES|DESede|3DES|RC4|AES/ECB|DES/ECB|DESede/ECB)[^\"]*\"",
        "crypto-003": r"Random\s*\(\s*\)",
        "infoleak-001": r"(API_KEY|PASSWORD|SECRET|TOKEN)\s*=\s*\"[^\"]+\"|println\s*\(\s*e(\.message)?",
    }

    go_patterns = {
        "sqli-001": r"fmt\.Sprintf\s*\(\s*\"[^\"]*SELECT[^\"]*%[svqd]",
        "xss-001": r"\.Write\s*\(\s*\[\]byte\s*\(\s*\"[^\"]*<[^\"\n]*\"\s*\+",
        "cmdi-001": r"exec\.Command\s*\(\s*\"sh\"\s*,\s*\"-c\"\s*,\s*\w+",
        "pathtraversal-001": r"os\.(Open|ReadFile)\s*\(\s*\w+\s*\)",
        "deserialization-001": r"gob\.NewDecoder\s*\(.*\)\.Decode\s*\(",
        "ssrf-001": r"http\.(Get|Post|NewRequest)\s*\(\s*\w+",
        "crypto-001": r"\b(md5|sha1)\.(New|Sum)\s*\(",
        "crypto-002": r"\b(des|rc4)\.NewCipher\s*\(",
        "crypto-003": r"\brand\.(Int|Intn|Float32|Float64|Read)\s*\(",
        "infoleak-001": r"(password|secret|key|token)\s*:?=\s*\"[^\"]+\"|panic\s*\(\s*err\s*\)",
    }

    return {
        "java": java_patterns,
        "javascript": js_patterns,
        "typescript": js_patterns,
        "python": py_patterns,
        "php": php_patterns,
        "csharp": csharp_patterns,
        "kotlin": kotlin_patterns,
        "go": go_patterns,
    }


def get_patterns_for_language(language: str) -> Dict[str, str]:
    patterns = get_language_patterns()
    if language == "other":
        merged = {}
        for language_patterns in patterns.values():
            merged.update(language_patterns)
        return merged
    return patterns.get(language, {})


def get_extensions_for_language(language: str) -> List[str]:
    extensions = {
        "java": [".java"],
        "javascript": [".js", ".jsx"],
        "typescript": [".ts", ".tsx"],
        "python": [".py"],
        "php": [".php", ".phtml"],
        "csharp": [".cs"],
        "kotlin": [".kt", ".kts"],
        "go": [".go"],
    }
    if language == "other":
        merged = []
        for values in extensions.values():
            merged.extend(values)
        return merged
    return extensions.get(language, [".java"])


def get_active_cwes(ruleset: str) -> set:
    if ruleset == "top25":
        return {"CWE-89", "CWE-79", "CWE-78", "CWE-502", "CWE-22", "CWE-918", "CWE-287", "CWE-306", "CWE-639", "CWE-200", "CWE-328", "CWE-327", "CWE-330"}
    if ruleset == "owasp":
        return {"CWE-89", "CWE-79", "CWE-78", "CWE-502", "CWE-22", "CWE-918", "CWE-287", "CWE-306", "CWE-639", "CWE-200", "CWE-328", "CWE-327", "CWE-330", "CWE-352", "CWE-434"}
    if ruleset == "top10":
        return {"CWE-89", "CWE-79", "CWE-78", "CWE-502", "CWE-22", "CWE-918", "CWE-287", "CWE-306", "CWE-639"}
    return {rule[1] for rule in RULE_DEFINITIONS}
