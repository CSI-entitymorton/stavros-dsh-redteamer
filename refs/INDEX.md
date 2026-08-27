# Refs index — pick doc + section HERE, then grep INSIDE the doc.

Docs are 30–65KB. Never read one end-to-end: `grep -n "<topic>" <doc>` then read only that region (offset/limit around the matching lines).

| doc | bytes | topics |
|---|---|---|
| `refs/README.md` | 18K | pentest 参考手册库（refs/） · 快速路由（按任务类型找目录） · 目录索引 · 来源与说明 · 路径与链接约定 |
| `refs/ai/ai-agent-safety.md` | 10K | AI Agent 安全 — 完整攻防手册 · 适用场景 · 前置条件 · Part A：攻击方法论 · Part B：防御体系 · 实战工具链 |
| `refs/ai/ai-assisted-hunting.md` | 5K | AI 辅助非预期挖掘技巧集 · 核心理念：目标驱动，不给打法 · 技巧 1：报错吐凭证（fuzz 的非预期出口） · 技巧 2：CDN 桶 → 真实桶溯源 · 技巧 3：base 服务业务语义枚举 · 技巧 4：业务字段字典构造（替代公开字典） |
| `refs/ai/ai-infra-attack-surface.md` | 3K | AI 基础设施攻击面（2026） · 1. 向量数据库（Milvus 实战三洞） · 2. 拖库语义：向量库 ≠ 普通数据库 · 3. LLM 网关与编排框架 · 4. 打点建议（渗透工作流挂点） · 来源 |
| `refs/ai/ai-jailbreak-techniques.md` | 6K | LLM 越狱技术 — 完整攻防手册 · 适用场景 · 前置条件 · Part A：攻击方法论 · Part B：防御体系 · 实战工具链 |
| `refs/ai/ai-model-security.md` | 65K | AI/ML 模型安全与深度伪造防御 — 完整攻防手册 · 适用场景 · Part A：攻击方法论 · Part B：检测与防御 · 速查表 · MITRE ATT&CK 映射 |
| `refs/ai/ai-prompt-injection.md` | 67K | AI 提示注入与 LLM 安全 — 完整攻防手册 · 适用场景 · 前置条件 · Part A：攻击方法论 · Part B：检测与防御 · CRITICAL SECURITY RULES (DO NOT VIOLATE) |
| `refs/ai/ai-rag-poisoning.md` | 9K | RAG 系统安全 — 完整攻防手册 · 适用场景 · 前置条件 · Part A：攻击方法论 · Part B：防御体系 · 实战工具链 |
| `refs/ai/ai-system-prompt-extraction.md` | 7K | 系统提示词提取 — 完整攻防手册 · 适用场景 · 前置条件 · Part A：攻击方法论 · Part B：防御体系 · 实战工具链 |
| `refs/api/api-auth-and-jwt-abuse.md` | 3K | SKILL: API Auth and JWT Abuse — Token Trust, Header Tricks, and Rate Limits · 1. TOKEN TRIAGE · 2. QUICK ATTACK PICKS · 3. HIDDEN FIELDS AND BATCH ABUSE · 4. RATE LIMIT BYPASS FAMILIES · 5. NEXT ROUTING |
| `refs/api/api-authorization-and-bola.md` | 1K | SKILL: API Authorization and BOLA — Object Access, Function Access, and Mass Assignment · 1. CORE TEST LOOP · 2. TEST SURFACES · 3. QUICK PAYLOADS · 4. WHAT TESTERS MISS · 5. NEXT ROUTING |
| `refs/api/api-fuzzing.md` | 7K | API Fuzzing · 1. RESTler — Stateful REST API Fuzzing · 2. Manual API Fuzzing Techniques · 3. api-fuzzing-bug-bounty — Fuzzing Strategies for Bug Boun… · 4. Decision Tree · 5. Tools |
| `refs/api/api-recon-and-docs.md` | 1K | SKILL: API Recon and Docs — Endpoints, Schemas, and Version Surface · 1. PRIMARY GOALS · 2. RECON CHECKLIST · 3. WHAT TO EXTRACT FROM DOCS · 4. NEXT ROUTING |
| `refs/api/graphql-and-hidden-parameters.md` | 6K | SKILL: GraphQL 深度滥用与隐藏参数 — 完整攻防手册 · 0. 快速识别 · Part A：攻击方法论 · Part B：检测与防御 |
| `refs/api/grpc-security.md` | 4K | SKILL: gRPC 安全 · 0. 快速识别 · Part A：攻击方法论 · Part B：检测与防御 · 8. RELATED ROUTING |
| `refs/api/http2-specific-attacks.md` | 11K | SKILL: HTTP/2 Specific Attacks — Expert Attack Playbook · 0. RELATED ROUTING · 1. HTTP/2 ATTACK SURFACE OVERVIEW · 2. h2c (HTTP/2 CLEARTEXT) SMUGGLING · 3. PSEUDO-HEADER INJECTION · 4. HPACK COMPRESSION ATTACKS |
| `refs/api/http3-quic-attacks.md` | 7K | HTTP/3 / QUIC 协议攻击面与走私 — 完整攻防手册 · 0. 快速识别 · Part A：攻击方法论 · Part B：检测与防御 |
| `refs/api/sse-security.md` | 6K | SKILL: SSE（Server-Sent Events）安全 · 0. QUICK START · 1. PROTOCOL BASICS · Part A：攻击方法论 · Part B：检测与防御 · 10. RELATED ROUTING |
| `refs/api/websocket-security.md` | 13K | SKILL: WebSocket Security · 0. QUICK START · 1. PROTOCOL BASICS · 2. CROSS-SITE WEBSOCKET HIJACKING (CSWSH) · 3. TESTING WITH TOOLS · 4. COMMON VULNERABILITIES |
| `refs/cdn/README-fuck-cdn.md` | 11K | FUCK-CDN · 它能做什么 · 安装 · 使用 · 覆盖的 CDN · 完整方法清单 |
| `refs/cdn/fuck-cdn.md` | 45K | FUCK-CDN — 穷尽一切手段，扒光 CDN 的底裤，找到真实 IP · 调用方式 · API Key 配置 · 跨平台适配规则 · 核心原则 · 优先级分层 |
| `refs/components/cloud-postexploitation.md` | 4K | 云凭据后利用（拿到 AK/SK 之后怎么验证影响） · 0. 通用三步法（凭据 → 影响） · 1. AWS（SSRF 拿到 IMDS 临时凭据 / 泄露的 AK SK） · 2. 阿里云（AccessKey 泄露极常见：前端 app/小程序、OSS 直传配置） · 3. 腾讯云 / GCP / Azure（要点版） · 4. 证据与报告 |
| `refs/components/component-default-config-audit.md` | 5K | 组件挖掘方法论：默认值审计 + 修复 diff 盲区 · 1. 配置默认值审计（黑名单类） · 2. 修复 diff 双版本对比法（「修一半」追挖） · 3. 特殊 IP 语义绕过（SSRF 防护的通用缝隙） · 4. 自动化/Flow 类功能的匿名触发面 · 5. 「配置责任组合即漏洞」的定性口径 |
| `refs/components/container-security.md` | 5K | 容器与 K8s 攻击面（黑盒视角） · 1. 暴露端口速查（侦察阶段指纹） · 2. Docker API 未授权（2375） · 3. kubelet 10250 → 节点执行 · 4. 拿到 Pod 内 shell 后（K8s 场景标准动作） · 5. K8s 配置型弱点（ apiserver 视角） |
| `refs/components/database-exploitation.md` | 23K | 数据库渗透 — 完整攻防手册 · 适用场景 · 一、MySQL 渗透 · 二、MSSQL（SQL Server）渗透 · 三、Oracle 渗透 · 四、Redis 渗透 |
| `refs/components/java-framework-vulns.md` | 21K | Java 框架漏洞 — 完整攻防手册 · 适用场景 · 一、Fastjson 反序列化 · 二、Apache Shiro 反序列化 · 三、Spring 系列漏洞 · 四、Struts2 OGNL 表达式注入 |
| `refs/components/jndi-injection.md` | 8K | SKILL: JNDI Injection — Expert Attack Playbook · 0. RELATED ROUTING · 1. CORE MECHANISM · 2. ATTACK VECTORS · 3. JDK VERSION CONSTRAINTS AND BYPASS · 4. TOOLING |
| `refs/components/middleware-vulns.md` | 21K | 中间件与服务攻防 — 完整攻防手册 · 适用场景 · 一、Apache HTTP Server · 二、Nginx · 三、Microsoft IIS · 四、Apache Tomcat |
| `refs/components/unauthorized-access-common-services.md` | 9K | SKILL: Unauthorized Access to Common Services — Expert Attack Playbook · 0. RELATED ROUTING · 1. DISCOVERY — PORT SCANNING · 2. REDIS (PORT 6379) · 3. RSYNC (PORT 873) · 4. PHP-FPM / FASTCGI (PORT 9000) |
| `refs/miniprogram/e0e1wx-readme.md` | 2K | e0e1-wx-gui · 项目简介 · 主要能力 · 环境要求 · 快速开始 · 使用前必读 |
| `refs/miniprogram/e0e1wx-tools.md` | 8K | 工具配置与功能说明 · 目录 · 使用前检查 · 微信小程序版本配置 · 应用配置 · 抓包或代理转发导致无法回连 |
| `refs/miniprogram/miniprogram-security-core.md` | 148K |  · ❌ 红线（违反即失败） · ⚠️ 授权声明（必读） · 评估流程总览 · 快速决策树（从目标直达 Phase） · Phase 0：环境搭建 |
| `refs/miniprogram/wmp-package-readme.md` | 12K | 微信小程序安全评估流水线 · 架构 · 目录结构 · 前置条件 · 安装 · 启动流程（关键！顺序不能错） |
| `refs/miniprogram/wmpf-debugger.md` | 4K | WMPFDebugger · Support Status · Prerequisites · Quick Start · Screenshots · Disclaimer |
| `refs/mobile/android-pentesting-tricks.md` | 12K | SKILL: Android Pentesting Tricks — Expert Attack Playbook · 0. RELATED ROUTING · 1. SSL PINNING BYPASS · 2. COMPONENT EXPOSURE · 3. WEBVIEW VULNERABILITIES · 4. INTENT REDIRECTION |
| `refs/mobile/ios-pentesting-tricks.md` | 14K | SKILL: iOS Pentesting Tricks — Expert Attack Playbook · 0. RELATED ROUTING · 1. JAILBREAK VS NON-JAILBREAK TESTING · 2. KEYCHAIN EXTRACTION · 3. URL SCHEME HIJACKING · 4. UNIVERSAL LINKS EXPLOITATION |
| `refs/mobile/mobile-pentest-android.md` | 63K | Android 移动应用渗透测试 — 完整攻防手册 · 适用场景 · 前置条件 · Part A：攻击方法论 · Part B：检测与防御 · 速查表 |
| `refs/mobile/mobile-pentest-ios.md` | 71K | iOS 移动应用渗透测试 — 完整攻防手册 · 适用场景 · 前置条件 · Part A：攻击方法论 · Part B：检测与防御 · 速查表 |
| `refs/mobile/mobile-ssl-pinning-bypass.md` | 18K | SKILL: Mobile SSL Pinning Bypass — Expert Attack Playbook · 0. RELATED ROUTING · 1. SSL PINNING TYPES · 2. ANDROID BYPASS METHODS · 3. iOS BYPASS METHODS · 4. FRAMEWORK-SPECIFIC BYPASSES |
| `refs/offensive/capability-primitive-chaining.md` | 4K | 能力原语拼图（僵局破解思维） · 1. 原语抽象 · 2. RCE 等式（满足任意一条即成） · 3. 低危 → 原语映射（「鸡肋」翻译成拼图碎片） · 4. 状态空间搜索（无现成链时） · 5. 突破口清单（看到别走开） |
| `refs/offensive/hash-attack-techniques.md` | 14K | SKILL: Hash Attack Techniques — Expert Cryptanalysis Playbook · 0. RELATED ROUTING · 1. LENGTH EXTENSION ATTACK · 2. MD5 COLLISION ATTACKS · 3. SHA-1 COLLISION · 4. BIRTHDAY ATTACK |
| `refs/offensive/initial-access.md` | 37K | 初始访问与二进制漏洞利用 — 完整攻防手册 · 适用场景 · Part A：攻击方法论 · Part B：检测与防御 · 速查表 · MITRE ATT&CK 映射 |
| `refs/offensive/privilege-escalation.md` | 32K | Privilege Escalation — 完整攻防手册 · 适用场景 · 前置条件 · Part A：攻击方法论 · Part B：检测与防御 · 速查表 |
| `refs/trends/trends-2025-2026.md` | 5K | 2025–2026 渗透趋势速览（pentest 侧） · 1. OWASP Top 10:2025（2025-11 发布） · 2. OWASP Top 10 for LLM Applications 2025 · 3. 工具与工作流风向（2026） · 4. 2025 值得记住的研究与案例（2026-08-16 补充核实） · 来源清单（2026-08-16 核实） |
| `refs/web/WAF_PRODUCT_MATRIX.md` | 19K | WAF Product Matrix — Per-Product Bypass Reference · 0. How To Use This Matrix · 1. Cloudflare · 2. AWS WAF · 3. ModSecurity / OWASP CRS · 4. Akamai (Kona Site Defender / App & API Protector) |
| `refs/web/cmdi-command-injection.md` | 19K | SKILL: OS Command Injection — Expert Attack Playbook · 0. RELATED ROUTING · 1. SHELL METACHARACTERS (INJECTION OPERATORS) · 2. COMMON VULNERABLE CODE PATTERNS · 3. BLIND COMMAND INJECTION — DETECTION · 4. INJECTION CONTEXT VARIATIONS |
| `refs/web/crlf-injection.md` | 4K | SKILL: CRLF Injection — Expert Attack Playbook · 0. RELATED ROUTING · 1. CORE CONCEPT · 2. DETECTION · 3. EXPLOITATION SCENARIOS · 4. FILTER BYPASS |
| `refs/web/csp-bypass-advanced.md` | 12K | SKILL: CSP Bypass — Advanced Techniques · 0. RELATED ROUTING · 1. CSP DIRECTIVE REFERENCE MATRIX · 2. BYPASS TECHNIQUES BY DIRECTIVE · 3. CSP IN META TAG vs. HEADER · 4. DATA EXFILTRATION DESPITE CSP |
| `refs/web/csv-formula-injection.md` | 4K | SKILL: CSV Formula Injection · 0. QUICK START · 1. DDE INJECTION (EXCEL / LIBREOFFICE) · 2. OBFUSCATION · 3. GOOGLE SHEETS · 4. TESTING METHODOLOGY |
| `refs/web/dangling-markup-injection.md` | 13K | SKILL: Dangling Markup Injection — Exfiltration Without JavaScript · 0. RELATED ROUTING · 1. WHEN TO USE DANGLING MARKUP · 2. CORE TECHNIQUE · 3. EXFILTRATION VECTORS · 4. WHAT CAN BE STOLEN |
| `refs/web/dns-rebinding-attacks.md` | 12K | SKILL: DNS Rebinding — Expert Attack Playbook · 0. RELATED ROUTING · 1. CORE PRINCIPLE · 2. TTL MANIPULATION · 3. ATTACK VARIANTS · 4. HIGH-VALUE TARGETS |
| `refs/web/email-header-injection.md` | 10K | SKILL: Email Header Injection — Expert Attack Playbook · 0. RELATED ROUTING · 1. SMTP HEADER INJECTION FUNDAMENTALS · 2. ATTACK SCENARIOS · 3. COMMON VULNERABLE PATTERNS · 4. SPF / DKIM / DMARC BYPASS TECHNIQUES |
| `refs/web/expression-language-injection.md` | 8K | SKILL: Expression Language Injection — Expert Attack Playbook · 0. RELATED ROUTING · 1. DETECTION — POLYGLOT PROBES · 2. SpEL (SPRING EXPRESSION LANGUAGE) · 3. OGNL (OBJECT-GRAPH NAVIGATION LANGUAGE) · 4. JAVA EL (JSP / JSF) |
| `refs/web/honeypot-detection.md` | 6K | SKILL: Web 蜜罐识别与反投喂 · 0. 为什么蜜罐识别是安全的一环 · Part A：识别方法 · Part B：检测与防御（防守方视角） · 7. RELATED ROUTING |
| `refs/web/http-host-header-attacks.md` | 11K | SKILL: HTTP Host Header Attacks — Injection & Routing Abuse · 0. RELATED ROUTING · 1. ATTACK SURFACE · 2. PASSWORD RESET POISONING · 3. WEB CACHE POISONING VIA HOST · 4. SSRF VIA HOST ROUTING |
| `refs/web/http-parameter-pollution.md` | 6K | SKILL: HTTP Parameter Pollution (HPP) · 0. QUICK START · 1. SERVER BEHAVIOR MATRIX · 2. PAYLOAD PATTERNS · 3. ATTACK SCENARIOS · 4. TOOLS |
| `refs/web/ldap-injection.md` | 5K | LDAP注入漏洞测试 · 概述 · 漏洞原理 · LDAP基础 · 测试方法 · 利用技术 |
| `refs/web/open-redirect.md` | 11K | SKILL: Open Redirect — Expert Attack Playbook · 1. CORE CONCEPT · 2. FINDING REDIRECT PARAMETERS · 3. FILTER BYPASS TECHNIQUES · 4. EXPLOITATION CHAINS · 5. TESTING CHECKLIST |
| `refs/web/path-traversal-lfi.md` | 23K | SKILL: Path Traversal / Local File Inclusion (LFI) — Expert Attack Playbook · 0. RELATED ROUTING · 1. CORE CONCEPT · 2. TRAVERSAL SEQUENCE VARIANTS · 3. TARGET FILES AND ESCALATION TARGETS · 4. PHP LFI → RCE TECHNIQUES |
| `refs/web/prototype-pollution-advanced.md` | 11K | SKILL: Prototype Pollution Advanced — RCE & Gadget Exploitation · 0. RELATED ROUTING · 1. SERVER-SIDE PP → RCE · 2. CLIENT-SIDE PROTOTYPE POLLUTION · 3. DETECTION TECHNIQUES · 4. BYPASS `__proto__` FILTERS |
| `refs/web/prototype-pollution.md` | 8K | SKILL: Prototype Pollution — Expert Attack Playbook · 0. QUICK START · 1. MECHANISM · 2. CLIENT-SIDE DETECTION · 3. SERVER-SIDE DETECTION (Express / Node, black-box) · 4. EXPLOITATION GADGETS |
| `refs/web/race-condition.md` | 21K | SKILL: Race Conditions — Testing & Exploitation Playbook · 0. QUICK START — What to Test First · 1. CORE CONCEPT · 2. ATTACK PATTERNS · 3. HTTP/1.1 LAST-BYTE SYNCHRONIZATION · 4. HTTP/2 SINGLE-PACKET ATTACK |
| `refs/web/recon-and-methodology.md` | 11K | SKILL: Recon and Methodology — Expert Bug Bounty Playbook · 1. RECON HIERARCHY · 2. SUBDOMAIN ENUMERATION (CRITICAL FIRST STEP) · 3. SERVICE AND PORT DISCOVERY · 4. WEB TECHNOLOGY FINGERPRINTING · 5. ENDPOINT DISCOVERY |
| `refs/web/subdomain-takeover.md` | 10K | SKILL: Subdomain Takeover — Detection & Exploitation Playbook · 0. RELATED ROUTING · 1. CORE CONCEPT · 2. DETECTION METHODOLOGY · 3. SERVICE PROVIDER FINGERPRINT TABLE · 4. TAKEOVER PROCEDURE — COMMON PROVIDERS |
| `refs/web/type-juggling.md` | 11K | SKILL: PHP Type Juggling — Weak Comparison & Magic Hash Bypass · 0. QUICK START · 1. LOOSE COMPARISON (`==`) — TRUTH TABLE & VERSIONS · 2. MAGIC HASHES (`0e…` + digits only) · 3. HMAC BYPASS (LOOSE COMPARE VS `"0"` OR `0`) · 4. NULL JUGGLING (ARRAYS & TYPE ERRORS) |
| `refs/web/waf-bypass-techniques.md` | 16K | SKILL: WAF Bypass Techniques — Evasion Playbook · 0. RELATED ROUTING · 1. PHASE 0 — IDENTIFY THE WAF · 2. GENERIC BYPASS CATEGORIES · 3. PROTOCOL-LEVEL BYPASS TECHNIQUES · 4. WAF BYPASS DECISION TREE |
| `refs/web/web-api-security.md` | 36K | Web API 安全 — 完整攻防手册 · 适用场景 · Part A：攻击方法论 · Part B：OWASP API Top 10 检查清单 · Part C：Postman 自动化测试 · 速查表 |
| `refs/web/web-auth-bypass.md` | 51K | Web 认证与授权绕过 — 完整攻防手册 · 适用场景 · Part A：攻击方法论 · Part B：检测与防御 · 速查表 · MITRE ATT&CK 映射 |
| `refs/web/web-cache-attacks.md` | 63K | Web 缓存攻击 — 完整攻防手册 · 适用场景 · Part A：攻击方法论 · Part B：检测与防御 · 速查表 · MITRE ATT&CK 映射 |
| `refs/web/web-csrf-cors-clickjacking.md` | 38K | CSRF / CORS / Clickjacking / CSP — 完整攻防手册 · 适用场景 · Part A：攻击方法论 · Part B：检测与防御 · 速查表 · MITRE ATT&CK 映射 |
| `refs/web/web-deserialization.md` | 37K | 不安全反序列化 — 完整攻防手册 · 适用场景 · Part A：攻击方法论 · Part B：检测与防御 · 速查表 · MITRE ATT&CK 映射 |
| `refs/web/web-file-handling.md` | 48K | 文件操作漏洞 — 完整攻防手册 · 适用场景 · Part A：攻击方法论 · Part B：检测与防御 · 速查表 · MITRE ATT&CK 映射 |
| `refs/web/web-injection-sqli.md` | 32K | SQL 注入 — 完整攻防手册 · 适用场景 · Part A：攻击方法论 · Part B：检测与防御 · 速查矩阵 · MITRE ATT&CK 映射 |
| `refs/web/web-injection-ssrf.md` | 59K | SSRF 服务端请求伪造 — 完整攻防手册 · 适用场景 · Part A：攻击方法论 · Part B：检测与防御 · 速查表 · MITRE ATT&CK 映射 |
| `refs/web/web-injection-xss.md` | 60K | XSS 跨站脚本 — 完整攻防手册 · 适用场景 · Part A：攻击方法论 · script-src 'unsafe-inline' → 直接注入（已允许内联） · script-src 'nonce-xxx' → 需要获取 nonce（通常不可行，除非有其他漏洞） · script-src 'self' → JSONP 端点绕过 |
| `refs/web/web-injection-xxe-ssti-nosql.md` | 53K | XXE / SSTI / NoSQL 注入 — 完整攻防手册 · 适用场景 · Part A-1：XXE 攻击 · Part A-2：SSTI 攻击 · Part A-3：NoSQL 注入 · 速查表 |
| `refs/web/web-logic-vulns.md` | 35K | Web 业务逻辑漏洞 — 完整攻防手册 · 适用场景 · Part A：攻击方法论 · Part B：检测与防御 · Part C：2025-2026 更新 · 速查表 |
| `refs/web/web-pentest-comprehensive.md` | 32K | Web 应用渗透测试 — 完整手册 · 适用场景 · Part A：攻击方法论 · 1. 执行摘要 · 2. 测试范围 · 3. 漏洞详情（每个漏洞） |
| `refs/web/web-request-smuggling.md` | 50K | HTTP 请求走私 / Host 头 / 参数污染 — 完整攻防手册 · 适用场景 · Part A：攻击方法论 · Part B：检测与防御 · 速查表 · MITRE ATT&CK 映射 |
| `refs/web/xpath-injection.md` | 6K | XPath注入漏洞测试 · 概述 · 漏洞原理 · XPath基础 · 测试方法 · 利用技术 |
| `refs/web/xslt-injection.md` | 10K | SKILL: XSLT Injection — Testing Playbook · 0. QUICK START · 1. VENDOR DETECTION · 2. EXTERNAL ENTITY (XXE VIA XSLT) · 3. FILE READ VIA `document()` · 4. FILE WRITE VIA EXSLT (`exslt:document`) |
| `refs/zh/arbitrary-x-authz.md` | 20K | 任意 X 子授权——比 IDOR 更狠的"权限维度"漏洞 · 1. 一句话区分 · 2. 6 个子类别 × 高危占比 · 3. 任意账号——最值钱的子类（86.4%） · 4. 任意用户注册（75.0%） · 5. 任意操作（72.5%）——最容易被低估 |
| `refs/zh/banking-finance.md` | 14K | 银行 / 金融行业渗透 playbook · 1. 一句话定位 · 2. 攻击面分层模型 · 3. 高危漏洞类型分布（金融特化） · 4. 银行特有攻击场景 · 5. 高价值目标资产 |
| `refs/zh/chinese-srcfingerprints.md` | 14K | 国产组件指纹 + 路径 + 高频参数字典 · 1. 国产 OA / 中间件指纹 · 2. 国产高危默认路径 · 3. 高频参数字典（基于 27,732 SQLi + 业务案例） · 4. 高频 URL 路径模式（fuzzing 字典） · 5. 文件指纹检测一行命令 |
| `refs/zh/default-credentials-cn.md` | 9K | 国产服务 / OA / CMS / 网络设备默认凭据 · 1. 国产 OA / 协同办公（核心战场） · 2. 国产中间件 / 数据库管理 · 3. 国产监控 / 工单 / IT 运维 · 4. 国产 CMS · 5. 国产网络设备 / 网管系统（运营商场景） |
| `refs/zh/dos.md` | 27K | 拒绝服务（DoS） · 1. 一句话说清是什么 + 为什么 SRC 关注 · 2. 攻击类型分类 · 3. 高频入口点（端点/参数/Header） · 4. 探测手法（黑盒视角） · 5. 利用与影响升级 |
| `refs/zh/dynamic-waf-reverse.md` | 7K | 动态 JS 混淆型 WAF 对抗（瑞数 / 数美类）— 逆向定位 → 签名还原 → 补环境重放 · 0. 为什么这类 WAF 不一样 · Part A：攻击方法论 · Part B：检测与防御（风控侧） |
| `refs/zh/info-disclosure.md` | 15K | 信息泄露 / 敏感文件 / 备份 · 1. 一句话说清 · 2. 高频入口点（按命中率排序） · 3. 探测手法 · 4. Bypass 矩阵 · 5. 利用提权 / 横向（链路放大） |
| `refs/zh/logic-flaws.md` | 50K | 业务逻辑 / 越权 / 验证码 / 支付篡改 · 1. 一句话说清 · 2. 高频入口点（按 WooYun 8,292 案例归类） · 3. 探测手法（按子类分） · 4. Bypass 矩阵 · 5. 利用提权 / 横向 |
| `refs/zh/methodology/00-index.md` | 2K | 方法论入口 · 这套方法论怎么用 · 与 SRC 平台的对齐 · 价值排序（精简版） · 配套 playbook 目录 |
| `refs/zh/methodology/01-attack-priority.md` | 6K | 攻击路径最短原则——黑盒猎手版 · 1. 一句话原则 · 2. 四维评分（每维 0–3 分，总分 0–12） · 3. 漏洞类型 × 默认价值矩阵 · 4. 价值升级链（Chain to escalate） · 5. 9 类敏感操作 × 黑盒优先级 |
| `refs/zh/methodology/02-bypass-toolkit.md` | 11K | 通用绕过工具箱 · 1. 绕过的本质 · 2. SQLi 绕过表（分维度） · 3. XSS 绕过表 · 4. 命令注入绕过表 · 5. 路径遍历 / 文件读绕过表 |
| `refs/zh/methodology/03-evidence-discipline.md` | 7K | 黑盒证据纪律 · 1. 一句话原则 · 2. 黑盒"幻觉"是怎么产生的 · 3. 黑盒证据三原则 · 4. 复现率要求 · 5. DNSLog / 带外平台选择 |
| `refs/zh/methodology/04-control-gap-hunting.md` | 9K | 控制缺口（Control Gap）狩猎 · 1. 思维模型 · 2. 端点分类速查 · 3. 9 类操作 × 探针表 · 4. "新功能 5 分钟探针套餐" · 5. 控制缺口报告写法 |
| `refs/zh/methodology/05-srctimebox-priority.md` | 7K | SRC 时间盒优先级——基于 22,132 案例统计的高危占比排序 · 1. 一句话原则 · 2. 16 类漏洞的高危占比排名 · 3. SRC 时间盒打法（4 个模板） · 4. 与 `01-attack-priority.md` 的合用矩阵 · 5. 探针决策树（按时间盒预算） |
| `refs/zh/telecom-isp.md` | 11K | 电信 / 运营商 / ISP 渗透 playbook · 1. 一句话定位 · 2. 攻击面全景图 · 3. 高危漏洞类型分布 · 4. 不常见但高价值的攻击面 · 5. GetShell / 横向移动路径 |
| `refs/zh/tools/tools-burp-plugin-ecosystem.md` | 4K | Burp Suite 插件生态清单 · 分类索引 · 隐藏攻击面 / 参数发现 · 越权 / 授权 · 编码 / 加密变换 · 认证 / JWT |
| `refs/zh/tools/tools-encoding.md` | 6K | 编码解码 |
| `refs/zh/tools/tools-exploitation.md` | 9K | 漏洞利用 |
| `refs/zh/tools/tools-password-attacks.md` | 9K | 密码攻击 |
| `refs/zh/tools/tools-recon.md` | 15K | 信息收集 |
| `refs/zh/tools/tools-web-pentest.md` | 15K | Web渗透 |
| `refs/zh/unauth-access.md` | 13K | 未授权访问 / 默认凭据 · 1. 一句话说清 · 2. 高频入口点（统计 + 端口） · 3. 探测手法 · 4. Bypass 矩阵（拿到登录页之后的事） · 5. 利用提权 / 横向 |
| `refs/zh/waf-bypass-cn.md` | 9K | 国产 WAF 指纹库与针对性绕过 — 完整攻防手册 · Part A：攻击方法论 · Part B：检测与防御 |
| `refs/zh/waf-bypass-payloads.md` | 171K | WAF / EDR 绕过 Payload 集 · 类别索引 · 框架漏洞 · SQL/NoSQL注入 · API安全 · LFI/RFI文件包含 |
