# CodeAudit 项目完整规划

## 一、项目目标

打造一款 **轻量级、多语言、AI增强的代码审计 CLI**，定位在 Bandit 和 Semgrep 之间的空白地带：
- 比 Bandit 广（多语言）
- 比 Semgrep 轻（零配置，pip 即用）
- 比 codex-security 免费（开源，支持本地 LLM）
- 比所有工具都多一个能力：AI 误报过滤

## 二、功能全景图

```
┌──────────────────────────────────────────────────────────────┐
│                     CodeAudit 功能全景                        │
├──────────────────────────────────────────────────────────────┤
│  已完成 (Phase 1)              │  待开发 (Phase 2-3)          │
├──────────────────────────────────────────────────────────────┤
│  ✅ Python 审计 (10条规则)      │  🔲 JS/TS 审计 (8条规则)    │
│  ✅ CLI 基本命令                │  🔲 Go 审计 (6条规则)       │
│  ✅ 规则过滤 --rules            │  🔲 Rust 审计 (6条规则)     │
│  ✅ 严重度过滤 --min-severity   │  🔲 AI 误报过滤 --ai       │
│  ✅ 路径忽略 .codeauditignore   │  🔲 自动修复 --fix         │
│  ✅ 配置文件 pyproject.toml     │  🔲 SARIF 输出             │
│  ✅ 中英双语输出                │  🔲 PyPI 发布              │
│  ✅ JSON + Markdown 报告        │  🔲 交互式配置 codeaudit init│
│  ✅ CI 自动测试 (4版Python)     │  🔲 更多规则 (每条20+条)    │
│  ✅ 67 测试 / 97% 覆盖率        │  🔲 规则市场 (用户贡献)     │
└──────────────────────────────────────────────────────────────┘
```

## 三、阶段分解

### Phase 1 ✅ 已完成

**Python 代码审计** — 10 条规则，完整 CLI，质量体系

| 模块 | 状态 |
|------|------|
| 安全规则 (S001-S003) | ✅ |
| 质量规则 (Q001-Q005) | ✅ |
| 性能规则 (P001-P002) | ✅ |
| CLI scan/rules 命令 | ✅ |
| 配置系统 (pyproject.toml + .codeauditignore) | ✅ |
| 过滤 (--rules, --min-severity) | ✅ |
| 中英双语 | ✅ |
| JSON + Markdown 输出 | ✅ |
| 测试体系 (67 tests, 97% coverage) | ✅ |
| CI (GitHub Actions, 4 Python 版本) | ✅ |
| GitHub 仓库 + README + CONTRIBUTING | ✅ |

### Phase 2 🔜 本周目标（第 2 周）

**多语言扩展 + AI 增强** — 从 Python 工具升级为多语言审计平台

**子目标 2.1：JavaScript/TypeScript 审计（D1-D3）**

目标任务：
- [ ] 引入 tree-sitter 解析器（同时支持 Python + JS/TS）
- [ ] JS/TS 安全规则（8条）：
  - S001  SQL 注入（NoSQL/MongoDB 也覆盖）
  - S002  密钥泄露
  - S003  eval/Function 危险函数
  - S004  XSS (innerHTML, dangerouslySetInnerHTML)
  - S005  命令注入 (child_process)
  - S006  prototype pollution
  - S007  不安全正则 (ReDoS)
  - S008  硬编码 URL/Token
- [ ] 规则引擎统一（Python 和 JS 规则共用同一套 Finding/Report 机制）
- [ ] 测试：每条规则至少 2 个正向 + 1 个负向测试

**子目标 2.2：Go 语言审计（D4-D5）**

目标任务：
- [ ] 添加 tree-sitter-go 解析器
- [ ] Go 安全规则（6条）：
  - S001  SQL 注入
  - S002  密钥泄露
  - S003  exec.Command 命令注入
  - S004  unsafe 包使用
  - S005  XSS (html/template 误用)
  - S006  hardcoded credentials

**子目标 2.3：AI 误报过滤（D6-D7）**

目标任务：
- [ ] LLM 客户端（支持 OpenAI API / OpenRouter / 本地 ollama）
- [ ] `--ai` 模式：将扫描结果 + 代码片段发给 AI 验证
- [ ] AI 置信度标记（每个 finding 加 `ai_verified` 字段）
- [ ] 降低误报率到接近零（筛选后只保留 AI 确认的）
- [ ] 测试：Mock LLM 验证管道

### Phase 3 🏁 第 3 周

**自动修复 + 发布筹备**

**子目标 3.1：自动修复（D1-D3）**

- [ ] `--fix` 交互式模式：逐个展示修复方案，用户确认
- [ ] `--fix --all` 批量模式：直接应用修复
- [ ] 修复预览（diff 格式）
- [ ] 每条规则配一个 fix 函数
- [ ] 回滚支持（git checkout 自动备份）

**子目标 3.2：SARIF 输出 + CI 集成（D4-D5）**

- [ ] SARIF 2.0 输出格式（GitHub Code Scanning 兼容）
- [ ] GitHub Actions 一键集成 Action
- [ ] 覆盖率提升到 99%+（补全缺失分支）

**子目标 3.3：发布筹备（D6-D7）**

- [ ] PyPI 发布（`pip install codeaudit`）
- [ ] GitHub Release（含 CHANGELOG）
- [ ] 首页截图 + Demo GIF
- [ ] 发布文章（掘金 / V2EX / Hacker News）
- [ ] 规则数量：Python 20+ 条 + JS 8 条 + Go 6 条 = 34+ 条

## 四、最终交付标准

| 指标 | 目标 |
|------|------|
| 支持语言 | Python + JavaScript + Go |
| 规则总数 | 34+ 条 |
| 测试总数 | 150+ |
| 覆盖率 | 97%+ |
| 安装方式 | pip install codeaudit |
| CI | 4 版本 Python 全通过 |
| 发布 | PyPI + GitHub Release |
| AI 模式 | 可选，支持 OpenAPI + ollama |

## 五、风险与应对

| 风险 | 应对 |
|------|------|
| tree-sitter 编译慢 | 使用预编译 wheel，不要求用户本地编译 |
| LLM API 成本 | 默认不启用，用户自行配置；支持本地模型 |
| JS 规则误报 | 每条规则配测试用例，AI 二次过滤兜底 |
| 时间不够 | Phase 3 部分可推迟到发布后 |
