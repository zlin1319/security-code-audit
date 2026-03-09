# Security Code Audit Skill

基于 Claude Agent Skills 规范的自动化安全代码审计工具。

## 目录结构

```text
security-code-audit/
├── SKILL.md                      # Skill 入口说明
├── README.md                     # 完整使用指南
├── 使用场景说明.md              # 场景化说明
├── .gitignore                    # 忽略缓存、报告和临时文件
├── pyproject.toml                # 安装和 CLI 入口定义
├── security_code_audit/
│   ├── audit.py                  # 包内主入口：CLI、扫描调度、报告输出
│   ├── rules.py                  # 多语言规则定义
│   ├── config_loader.py          # 配置文件发现和解析
│   ├── suppressions.py           # ignore / suppress 处理
│   ├── context_analyzer.py       # 本地上下文与置信度修正
│   ├── ai_analyzer.py            # 可选 AI 增强验证
│   └── __main__.py               # `python -m security_code_audit`
├── scripts/
│   ├── audit.py                  # 兼容入口，转发到 package CLI
│   └── audit.sh                  # Shell 包装脚本
├── tests/
│   └── test_smoke.py             # CLI 主链路 smoke tests
├── assets/
│   ├── report-template.md        # Markdown 报告模板
│   ├── json-schema.json          # JSON 输出 Schema
│   ├── security-audit.toml.example
│   ├── security-audit.ignore.example
│   └── ci/                       # GitHub/GitLab/Azure CI 模板
├── examples/                     # 多语言漏洞样例
│   ├── java/
│   ├── javascript/
│   ├── python/
│   ├── php/
│   ├── csharp/
│   ├── kotlin/
│   └── go/
├── references/
│   ├── vulnerability-rules.md    # 漏洞规则说明
│   └── cwe-mapping.md            # CWE / OWASP 映射
└── reports/                      # 运行时输出目录（默认不入库）
    └── <scan-name>/
        ├── audit-report.json
        ├── audit-report.md
        ├── audit-report.sarif
        └── audit-report-ai.md
```

## 目录职责

| 目录 / 文件 | 作用 | 是否建议保留 |
|-------------|------|--------------|
| `security_code_audit/` | 核心实现，真正执行扫描、过滤和输出报告 | 保留 |
| `scripts/` | 兼容入口和 shell 包装 | 保留 |
| `tests/` | 最小回归测试，防止 CLI 主流程被改坏 | 保留 |
| `examples/` | 多语言样例，便于 demo 和回归验证 | 保留 |
| `assets/` | 报告模板、CI 模板、配置示例 | 保留 |
| `references/` | 规则来源和映射说明 | 保留 |
| `reports/` | 每次运行生成的输出目录 | 不入库，按需生成 |
| `.gitignore` | 防止缓存、报告、系统文件再次进入仓库 | 保留 |

## 架构设计

```text
CLI / Skill Input
        |
        v
Config Load -> Path / Language / Ruleset / Ignore Resolution
        |
        v
File Discovery -> Full Repo or PR/MR Changed Files
        |
        v
Regex Rule Matching (multi-language)
        |
        v
Context Analyzer
- source / sink hints
- sanitizer hints
- confidence adjustment
- inline suppression / ignore filtering
        |
        v
Optional AI Validation (--use-ai)
        |
        v
Report Writers
- audit-report.json
- audit-report.md
- audit-report.sarif
- audit-report-ai.md
```

### 核心组件说明

| 组件 | 功能 | 技术实现 |
|------|------|----------|
| **security_code_audit.audit** | CLI、扫描编排、报告输出 | `argparse` / `pathlib` / `json` |
| **security_code_audit.rules** | 按语言加载规则与正则模式 | Python `re` |
| **security_code_audit.config_loader** | 加载 `.security-audit.toml/.json/.yaml` | `tomllib` / `json` / `yaml` |
| **security_code_audit.suppressions** | 路径忽略、ignore file、行内 suppress | glob / comment scan |
| **security_code_audit.context_analyzer** | 做局部上下文判断和置信度修正 | source/sink/sanitizer heuristics |
| **security_code_audit.ai_analyzer** | 对 findings 做可选 AI 增强验证 | local rule-based + AI prompt flow |

## 快速开始

### 安装

推荐先做可编辑安装：

```bash
python3 -m pip install -e .
```

安装后可直接使用：

```bash
security-code-audit --path ./src --language java
```

也可以继续使用模块入口：

```bash
python3 -m security_code_audit --path ./src --language java
```

如果需要 YAML 配置文件支持，再额外安装：

```bash
python3 -m pip install pyyaml
```

### 三条命令跑 Demo

```bash
cd /path/to/security-code-audit
./scripts/audit.sh examples/java/VulnerableController.java java all
cat reports/VulnerableController/audit-report.md
```

### 使用 Python 直接运行

```bash
python3 -m security_code_audit \
  --path /path/to/code \
  --language php \
  --ruleset all \
  --confidence medium
```

### 兼容旧入口

```bash
python3 scripts/audit.py --path /path/to/code --language php
```

### AI 增强扫描（自动分析）

```bash
python3 -m security_code_audit \
  --path /path/to/code \
  --language java \
  --auto-ai
```

扫描完成后会自动生成 AI 分析提示，直接说 "AI深度分析" 即可让我验证结果。

### 对话 / Skill 模式

如果是在 Claude Code / Codex 这类对话式 Agent 环境里使用，优先用 wrapper：

```bash
./scripts/skill_scan.sh --path /path/to/code --language java
```

只有在需要调试 wrapper 或直接走底层 CLI 时，再用：

```bash
python3 -m security_code_audit \
  --skill-mode \
  --path /path/to/code \
  --language java
```

`--skill-mode` 会自动：
- 开启 `--use-ai`
- 开启 `--auto-ai`
- 生成 `audit-report-ai.md`
- 生成 `ai-analysis-prompt.txt`
- 在发现 `high` / `critical` 时仍返回退出码 `0`，避免对话式宿主把“有漏洞”误判成“执行失败”

### 生成英文报告

```bash
python3 -m security_code_audit \
  --path /path/to/code \
  --language java \
  --output ./reports \
  --report-lang en
```

使用 `--report-lang en` 参数生成英文版安全审计报告。

### PR/MR 增量扫描

```bash
python3 -m security_code_audit \
  --path ./src \
  --language go \
  --git-diff-range origin/main...HEAD
```

也可以通过 CI 传入变更文件清单：

```bash
python3 -m security_code_audit \
  --path ./src \
  --language go \
  --changed-files-file .changed-files.txt
```

## 开源版 vs 企业版

| 功能特性 | 开源版 | 企业版 |
|----------|--------|--------|
| 基础SAST扫描 | ✅ | ✅ |
| 完整CWE Top 25覆盖 | ⚠️ 部分规则 | ✅ 全部规则 |
| 软件成分分析(SCA) | ❌ | ✅ 检测第三方组件漏洞 |
| 自定义规则引擎 | ❌ | ✅ 支持企业私有规则 |
| 高级误报过滤 | ❌ | ✅ AI增强分析 |
| 批量扫描支持 | ❌ | ✅ CI/CD集成 |
| 技术支持 | 社区支持 | 优先支持 |

**使用企业版：**
```bash
python3 -m security_code_audit \
  --path ./src \
  --language java \
  --api-key YOUR_ENTERPRISE_API_KEY
```

企业版报告底部不会显示升级提示。联系商务获取 API Key。

## 参数说明

| 参数 | 说明 | 可选值 | 默认值 |
|------|------|--------|--------|
| `--path` | 代码路径（文件或目录） | 任意路径 | - |
| `--language` | 目标语言 | `java`, `javascript`, `typescript`, `python`, `php`, `csharp`, `kotlin`, `go`, `other` | - |
| `--ruleset` | 规则集 | `top25`, `owasp`, `top10`, `all` | `all` |
| `--confidence` | 最小置信度阈值 | `high`, `medium`, `low` | `low` |
| `--config` | 配置文件路径 | TOML / JSON / YAML | 自动发现 `.security-audit.*` |
| `--exclude` | 排除扫描的 glob 模式 | 空格分隔 glob | - |
| `--ignore-file` | 从文件读取忽略模式 | 换行分隔 glob | - |
| `--changed-files` | 仅扫描指定变更文件 | 空格或逗号分隔路径列表 | - |
| `--changed-files-file` | 从文件读取变更文件列表 | 换行分隔文件路径 | - |
| `--git-diff-range` | 仅扫描指定 Git diff 范围内的文件 | 如 `origin/main...HEAD` | - |
| `--output` | 输出目录 | 任意路径 | `reports/<project-name>/` |
| `--skill-mode` | 对话 / skill 模式，自动开启 AI 产物并对 findings 返回退出码 `0` | - | - |
| `--auto-ai` | 自动生成 AI 分析提示（Claude Code 集成） | - | - |
| `--report-lang` | 报告语言 | `zh` (中文), `en` (英文) | `zh` |
| `--api-key` | 企业版 API Key（用于启用完整扫描能力） | 您的企业授权密钥 | - |

## 开发者指南

如果你要维护这个项目，推荐先看：

- [DEVELOPMENT.md](DEVELOPMENT.md)
- [RELEASE.md](RELEASE.md)
- [CHANGELOG.md](CHANGELOG.md)

其中包含：

- `pip install -e .` 的开发安装方式
- package 结构说明
- 测试与回归命令
- 新增规则 / 语言时需要同步的文件
- 兼容入口策略：`python -m security_code_audit`、`scripts/audit.py`、`scripts/audit.sh`

## 漏洞覆盖

当前开源版本地规则引擎实际实现并默认启用以下规则；更复杂的存储型 XSS、鉴权缺失、IDOR 等场景仍建议结合 AI 研判或企业版能力处理。

### CWE Top 25 (2023)

| CWE | 名称 | 规则 ID |
|-----|------|---------|
| CWE-89 | SQL Injection | sqli-001 |
| CWE-79 | XSS | xss-001 |
| CWE-78 | Command Injection | cmdi-001 |
| CWE-502 | Insecure Deserialization | deserialization-001 |
| CWE-22 | Path Traversal | pathtraversal-001 |
| CWE-918 | SSRF | ssrf-001 |
| CWE-328 | Weak Hash | crypto-001 |
| CWE-327 | Weak Encryption | crypto-002 |
| CWE-330 | Insecure Random | crypto-003 |
| CWE-200 | Information Leakage | infoleak-001 |

### OWASP Top 10 (2021)

- A01: Broken Access Control
- A02: Cryptographic Failures
- A03: Injection (SQLi, XSS, Command Injection)
- A05: Security Misconfiguration
- A07: Auth Failures
- A08: Data Integrity Failures
- A10: SSRF

## 输出 Schema

默认会生成三份报告：

- `audit-report.json`：机器可读结果
- `audit-report.md`：人工阅读报告
- `audit-report.sarif`：供 GitHub / Azure DevOps code scanning 上传

每条漏洞包含以下字段：

```json
{
  "rule_id": "sqli-001",
  "cwe": "CWE-89",
  "severity": "critical",
  "confidence": "high",
  "file": "Example.java",
  "line_range": { "start": 10, "end": 12 },
  "sink_source_summary": "污点流向摘要",
  "evidence_snippet": "代码片段",
  "reasoning": "漏洞原理说明",
  "fix_guidance": "修复建议",
  "safe_fix_example": "安全代码示例"
}
```

## SARIF 输出

`audit-report.sarif` 默认输出在报告目录下，可直接接入主流 code scanning 流程：

- GitHub: 使用 [assets/ci/github-code-scanning.yml](assets/ci/github-code-scanning.yml)
- Azure DevOps: 使用 [assets/ci/azure-pipelines.yml](assets/ci/azure-pipelines.yml)
- GitLab: 使用 [assets/ci/gitlab-ci.yml](assets/ci/gitlab-ci.yml) 发布 SARIF artifact

说明：根据 GitLab 当前官方集成要求，原生 Security Dashboard 需要 GitLab Secure JSON，而不是 SARIF；当前模板会把 SARIF 作为流水线 artifact 暴露，便于 MR 审阅和二次处理。

## 配置文件

工具会自动发现以下配置文件之一：

- `.security-audit.toml`
- `.security-audit.json`
- `.security-audit.yaml`
- `.security-audit.yml`

推荐使用 TOML，示例见 [assets/security-audit.toml.example](assets/security-audit.toml.example)。

常见字段：

- `path`
- `language`
- `ruleset`
- `confidence`
- `report_lang`
- `git_diff_range`
- `exclude`
- `ignore_file`

忽略模式示例见 [assets/security-audit.ignore.example](assets/security-audit.ignore.example)。

## 忽略与抑制

支持两类抑制方式：

- 路径级忽略：通过 `--exclude` 或 `--ignore-file`
- 行内抑制：在命中附近加注释 `security-code-audit: ignore <rule_id>`

示例：

```php
// security-code-audit: ignore sqli-001
$query = "SELECT * FROM users WHERE name = '" . $name . "'";
```

## 上下文分析

除了 regex 命中外，当前版本还会做一层轻量上下文分析：

- 识别常见 source 变量
- 检查 source 到 sink 的同名传播
- 检测常见 sanitization 痕迹
- 根据上下文动态调整 `confidence` 和 `sink_source_summary`

## 与 Claude Code 集成 (AI 增强)

在 Claude Code 环境中使用时，推荐直接走对话友好的 skill 模式：

```bash
# 单次扫描，自动生成 AI 相关产物
./scripts/skill_scan.sh --path ./src --language java
```

### 作为 Skill 使用

如果这是以 skill 形式被调用，推荐直接用自然语言触发：

```text
用 security-code-audit skill 扫描这个仓库
用 security-code-audit skill 扫描 ./service，语言 go
用 security-code-audit skill 只检查当前 PR/MR 改动
用 security-code-audit skill 按项目配置扫描
```

对应到底层脚本，通常等价于：

```bash
# 全库扫描
./scripts/skill_scan.sh --path ./src --language other

# Go 扫描
./scripts/skill_scan.sh --path ./service --language go

# PR/MR 增量扫描
./scripts/skill_scan.sh --path ./src --language other --git-diff-range origin/main...HEAD

# 按项目配置扫描
./scripts/skill_scan.sh --config .security-audit.toml
```

**AI 验证能力：**
- ✅ 识别误报（如 `PreparedStatement` 被误判为 SQL 注入）
- ✅ 追踪数据流（从 `@RequestParam` 到 `executeQuery`）
- ✅ 验证净化措施（检查是否有输入验证、编码转义）
- ✅ 生成定制修复代码

### 工作原理

```
┌──────────────────┐      ┌──────────────────┐
│   SAST Scanner   │      │   Claude Code    │
│   (audit.py)     │ ───→ │   (AI Analysis)  │
│                  │ JSON │                  │
│  • Regex Match   │      │  • Context Check │
│  • Rule Filter   │      │  • Flow Verify   │
│  • Taint Track   │      │  • Fix Generate  │
└──────────────────┘      └──────────────────┘
```

无需 API Key，完全利用 Claude Code 内置 AI 能力。

### 两种使用模式

| 模式 | 命令 | 适用场景 |
|------|------|----------|
| **传统扫描** | `python -m security_code_audit --path ./code --language java` | CI/CD 集成、快速扫描 |
| **Skill 模式** | `./scripts/skill_scan.sh --path ./code --language java` | 对话式审计、一次扫描自动带 AI 产物 |

### 高级用法

你也可以要求我：

1. **验证特定文件的安全性**
   > "请重点检查 UserController.java 的 SQL 注入漏洞"

2. **分析误报**
   > "这些发现中哪些是误报？"

3. **数据流追踪**
   > "追踪第 45 行的 SQL 注入，数据是如何从用户输入流到数据库查询的？"

4. **修复代码生成**
   > "为第 32 行的 XSS 漏洞生成修复代码"

### 工作原理

**Stage 1: SAST 扫描（本地脚本）**

```
┌──────────────┐  ┌──────────────┐  ┌──────────────┐
│ 输入源识别    │→│ 危险函数检测  │→│ 污点追踪      │
│ Source       │  │ Sink         │  │ Taint Track  │
│ @RequestParam│  │ executeQuery │  │ String + var │
└──────────────┘  └──────────────┘  └──────────────┘
```

**Stage 2: AI 验证（Claude Code / Skill 模式）**

在 `./scripts/skill_scan.sh` 或 `--skill-mode` 下，这一阶段会自动衔接：

1. **读取原始代码** - 不只是报告中的片段，而是完整函数上下文
2. **理解业务逻辑** - 识别输入验证、编码转义等安全措施
3. **追踪数据流** - 从 `@RequestParam` 到 `executeQuery` 的完整路径
4. **验证漏洞** - 判断是否可以实际利用
5. **生成修复** - 针对具体代码提供安全修复方案

## 最佳实践

### 1. 首次审计建议

```bash
# 使用完整规则集进行全面扫描
./scripts/skill_scan.sh --path ./src --language java --ruleset all
```

### 2. CI/CD 集成

```bash
# 使用传统模式（无 AI），设置适当的阈值
python -m security_code_audit \
  --path ./src \
  --language java \
  --ruleset top25 \
  --output reports/security-audit

# 生成的 SARIF 报告：
# reports/security-audit/audit-report.sarif
```

可直接复用仓库内模板：

- GitHub Actions: [assets/ci/github-code-scanning.yml](assets/ci/github-code-scanning.yml)
- GitLab CI: [assets/ci/gitlab-ci.yml](assets/ci/gitlab-ci.yml)
- Azure Pipelines: [assets/ci/azure-pipelines.yml](assets/ci/azure-pipelines.yml)

### 3. 增量审计

```bash
# 直接按 Git diff 范围扫描 PR/MR 改动
python -m security_code_audit \
  --path ./src \
  --language go \
  --git-diff-range origin/main...HEAD

# 或者由 CI 预先生成变更文件列表
git diff --name-only origin/main...HEAD > .changed-files.txt
python -m security_code_audit \
  --path ./src \
  --language go \
  --changed-files-file .changed-files.txt
```

## 故障排除

### 扫描未发现漏洞

可能原因：
1. 规则集选择太严格，尝试 `--ruleset all`
2. 置信度阈值太高，尝试 `--confidence low`
3. 代码确实安全，或漏洞模式不在当前规则覆盖范围内

### 误报太多

解决方案：
1. 优先使用 `./scripts/skill_scan.sh` 或 `--skill-mode`，默认会生成 AI 过滤结果
2. 提高置信度阈值 `--confidence high`
3. 使用 `--ruleset top25` 关注高风险漏洞

### 需要自定义规则

编辑 [security_code_audit/rules.py](security_code_audit/rules.py) 中的 `get_language_patterns()`：

```python
def get_language_patterns() -> Dict[str, Dict[str, str]]:
    return {
        "java": {
            "custom-rule": r"your-regex-pattern",
        },
    }
```

## 设计原则

### Progressive Disclosure

- **SKILL.md** 保持简洁，仅含核心信息
- **references/** 存放详细规则说明、CWE 映射表
- **assets/** 存放报告模板、JSON Schema
- 工具按需加载参考文档

### Exit Codes

| Code | 含义 |
|------|------|
| 0 | 无 Critical/High 漏洞 |
| 1 | 发现 High 漏洞 |
| 2 | 发现 Critical 漏洞 |

## 许可证

MIT License - 仅供安全测试和教育使用
