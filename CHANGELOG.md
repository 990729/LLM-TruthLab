# LLM-TruthLab 迭代更新日志 (Autonomous Iteration Changelog)

## v11.2.0
- **重磅升级：智商题库大幅扩容至 31 类 + 测评题量翻倍（4 路并发加速）** (`audit_engine/probes_iq_extended.py`, `probes_iq.py`) — 新增 14 种全新零污染动态出题引擎（辛普森悖论、调和均速、五元命题逻辑 SAT、DAG 关键路径、中文超额累进财务计算、容斥原理计数、大指数模幂、反贪心最短路、Python 闭包/可变默认参数追踪、AST 沙箱动态规划算法、SQLite GROUP BY HAVING 沙箱、三维骰子 8 步滚动姿态模拟、五重结构化筛选转换、新旧双文档冲突覆盖防幻觉）；测题量翻倍至 **快速 16–17 题 / 标准 31 题 / 深度 34 题**，并新增一键 **「纯测智商 (34题)」** 预设。
- **全面大白话与防误报校准**：默认开启 **AI 大白话解读**（调用当前 Key 输出 10 秒看懂的 5 行人话报告）+ 顶部醒目输出 **最可能真实模型（覆盖 2026 最新模型线与置信度%）**；针对 2026 新代模型与常见中转防封提示词做了去误报校准（不再因常规 50–260 字防封提示词或新模型不支持调温度/stop 而误报假货）。
- **全电脑自适应加固**：内嵌完整 `python314.dll`、`VCRUNTIME140`、`sqlite3`、`OpenSSL`、`certifi` 根证书，支持只读目录自动回落 `%LOCALAPPDATA%\LLM-TruthLab`、全屏/笔记本高分屏响应式适配、慢机 150 秒冷启动宽限，以及彻底修复 HTTP/1.1 Keep-Alive 心跳错位问题。

## v11.0.0
- **重磅重构：极简黑曜石高定桌面 UI** (`web/index.html`) — 全新 Apple / Linear 级极简暗黑质感界面（哑光黑曜石 `#08080a` + 象牙白主 CTA + 1px 精密发丝线 + 左侧精简 6 导航轨 + 渐进式披露高级抽屉 + 报告 4 子标签视图 + `Ctrl+Enter` 快捷键），清爽大气、零冗余杂乱。
- **新增：本地透明代理被动审计工作台** (`audit_engine/proxy_server.py`, `/api/proxy/*`) — 零额外 Token 消耗！在本地监听 `127.0.0.1:8899`，Cursor / Claude Code / Cherry Studio 指向它即可实时流式透传日常编码请求，后台静默统计花费、TTFT/TPS，并实时告警会话中途暗换模型、指纹跳变、机房切换与 `<think>` 泄露。
- **新增：隐身防反检模式（Stealth Mode）** (`client.py`, `probes_fingerprint.py`) — 伪装官方 SDK User-Agent 并动态改写指纹探针句式，防止黑心中转写规则识别测试流量并临时放真源。
- **新增：反网页逆向号池与同家族降级 6 联硬探针** (`audit_engine/probes_v11.py`, `png_gen.py`)：
  - `logit_bias` 精确 Token ID 狙击（封杀 `'7'` ID 22，一举拆穿网页逆向号池与非 tiktoken 词表）；
  - Prompt Cache 物理首字加速（TTFT 对比）与账号级粘性验证（专抓多账号轮询逆向池与假缓存字段）；
  - 旗舰模型「过快即假」物理吞吐异常审计（专抓 Haiku 冒充 Opus / Flash 冒充 Pro）；
  - 1024×1024 高清微缩角标视觉防降采样陷阱（专抓偷压缩图片或强改 `detail: low`）；
  - 5 轮有状态对话 `system` 权威抗越权与首轮反失忆探测；
  - 并行 3 工具调用 + 工具报错自愈闭环测试。
- **升级：10 维实用工程智商测评** (`probes_iq.py`) — 新增纯内存只读沙箱 **SQLite SQL 多表聚合考题**、**精准外科手术式行级补丁 Diff 考题（5 组单测 + 保护区锁）** 与 **私有反常识 API 规格 RAG 忠实度防幻觉考题**。
- **新增：控费与运维套件** — 单次**预算上限熔断器（¥）**、报告页**真实暗倍率计算器**、**域名一键匿名打码**、金丝雀定时巡检 **Webhook 告警推送**（支持飞书 / 钉钉 / 企微 / Discord / Slack + 测试按钮）、**备份 ZIP 一键导入还原** (`/api/backup/import`)。

## v10.0.0
- **新增：零消耗本地模拟黑心中转演练沙箱** (`audit_engine/demo_sandbox.py`, `/api/audit/demo`) — 欢迎页一键启动本地内存模拟掺水站（伪造签名放行 + 泄露 `<think>` + 正则改词洗白 + 假 `tiktoken` 账单 + 隐藏 System Prompt + 香港节点/OneAPI 响应头 + 低智商），零成本 3 秒完整体验全部证据链、8 维雷达图与战报 PNG 导出。
- **修复并加固：`auto` 协议自动识别 Schema 严格校验** (`client.py: detect_protocol`) — 解决部分中转站对 `/v1/messages` 返回 HTTP 200 却吐出 OpenAI `choices` JSON 时误判协议的边界坑，确保精准回落到真实兼容协议。
- **新增：一键打包备份全部本地基线与历史档案 ZIP** (`/api/backup/export`)，方便跨电脑迁移脱敏取证档案。
- **升级：基线比对表支持展开查看分任务 JSD 散度热力条**。
- **修复：Windows 中文环境 `--windowed` `.exe` CLI 输出 UTF-8 防崩溃与 SSE 干净断连** (`app.py`: `_configure_safe_stdio` + `Connection: close`)，彻底消除 GBK (`cp936`) 无法编码特殊符号导致的静默卡死，且在 `build_exe.ps1` 增加严格 `$LASTEXITCODE` 门禁。

## v9.0.0
- **新增：Cloudflare `cf-ray` 机场三字码出口机房定位与反代网关栈取证** (`audit_engine/net_forensics.py`) — 自动解码 HKG/SIN/NRT/SJC/LAX/FRA 等 20+ 全球边缘节点地理归属，识别 OneAPI / NewAPI / Veloera / Nginx / OpenResty / Envoy 网关栈并直接展示在前端遥测面板与离线 HTML 报告中。
- **新增：Assistant Prefill 尾消息续写行为指纹探针** (`probe_assistant_prefill`) — 探测端点对尾部 `assistant` 前缀消息的无缝续写、拒绝或忽略行为，作为协议行为辅助指纹。
- **新增：`--cli --ab` 命令行双端对决 / 一键别名打假模式** — 支持脚本自动化对决与自动继承同站 URL/Key，直接导出离线 A/B 对决 HTML 与 JSON 战报。
- **升级：离线 HTML 报告完整补齐官方参考折算成本、出口机房节点与 P50/P95/P99/CV 延迟抖动摘要**。

## v8.0.0
- **新增：内置「鉴假速查手册」弹窗** (`guideModal`) — 提供 Tokenizer 词表边界速查表（OpenAI o200k vs Claude BPE vs DeepSeek/Qwen vs Gemini）、JSD 散度判定阈值表、三大零误报铁证必杀判据，零基础也能秒懂报告。
- **新增：离线暗黑极客战报图 PNG 一键导出** (`exportPosterBtn`) — 纯离线 HTML5 Canvas 渲染 980×640 高清体检战报卡片（含零信任大结论、可信分、实时 8 维智商雷达图、底层归因、参考成本与核心异常摘录），自动脱敏可直接发群聊/论坛。
- **新增：中英双语精读智商题（中文财务大写数字 + 双重否定条件逻辑）** (`_build_bilingual_nuance`) — 每次动态随机生成中文大写门槛与双重否定评审规则，揪出用纯英文或弱中文小模型冒充多语种旗舰的替身。
- **新增：A/B 对决 & 批量红黑榜一键复制脱敏 Markdown 帖** (`copyArenaMarkdown`, `copyBatchMarkdown`)。

## v7.0.0
- **新增：无字像素柱状图视觉读数验真（反 OCR 文本中间件套壳）** (`png_gen.py: generate_chart_vision_image`, `probe_chart_vision_anti_ocr`) — 纯 stdlib 实时生成 4 根彩色立柱 + Y 轴刻度的像素柱状图（故意不在柱顶打印数字！），直接击穿“网关用便宜 OCR 提取文字再喂给纯文本模型”以及“换用极弱小视觉模型”的套壳手段。
- **新增：第二道 AST 沙箱可执行代码智商题——自定义优先级表达式解析器** (`_build_code_parser_challenge`) — 每次动态随机生成自定义二元运算符 `@`（`x @ y = k1*x - k2*y`，优先级高于 `*`、左结合），在隔离安全沙箱内用 6 组嵌套括号隐藏单测实时判分。
- **新增：全量请求延迟分布直方图 SVG、P99 与双峰路由抖动预警** (`latency_histogram`, `latency_jitter_cv`, `bimodal_latency_suspected`)。
- **新增：无 Key 安全常用站书签簿**（仅存地址/模型/协议/代理，绝不落盘 API Key）与 **批量红黑榜多行文本粘贴导入**（`标签 | URL | Key | 模型`）。

## v6.0.0
- **新增：客户端 UA 差异路由 / 看人下菜碟探测** (`probe_client_cloaking`) — 对比普通脚本 UA (`python-requests`) 与模拟 `claude-cli` / `Cursor` IDE 客户端请求头，抓获针对特定客户端放真源或专属掺水池的差异路由黑产。
- **新增：输出/推理 Token 物理生成速率反假账核验** (`audit_usage_physics_sanity`) — 交叉校验上报 `output_tokens`/`reasoning_tokens` 与真实端到端耗时，揪出 150ms 却虚报数千思考 Token 的假账单。
- **新增：一键复制脱敏 Markdown 测评报告** (`copyMdBtn`) — 一键生成带完整证据链与官方参考成本、自动隐藏 Key 的 Markdown 摘要，方便发论坛/群聊避坑分享。

## v5.0.0
- **新增：动态防缓存原生 PDF 解析验真** (`audit_engine/pdf_gen.py`, `probe_native_pdf`) — 纯 Python stdlib 实时生成合法 PDF 1.4 含随机校验码与算术题，发送至 Anthropic `type: "document"` 与 Gemini `inlineData`，直接抓获伪装原生协议的兼容转发层或丢弃 PDF 的套壳站。
- **新增：长输出防偷砍 `max_tokens` 上限探测** (`probe_output_cap`) — 专抓中转网关暗中将用户 `max_tokens` 压低至 256/512 导致长代码断尾的省钱黑招。
- **新增：官方公开参考价成本估算器** (`audit_engine/pricing.py`) — 每次体检后精确折算本次 Token 按官方公开价的 USD / CNY 成本，方便用户对照中转站后台扣费识别暗箱高倍率。
- **新增：4 套一键实战预设**（闪电打假 / 标准全检 / Agent专项 / 极限压测）与 **高级网络设置**（HTTP/SOCKS 代理、自签名 SSL 开关、超时、并发线程、自定义 Header JSON）。
- **新增：UI 前端 JS 自动语法检验**（测试集接入 `node --check` 验证零语法错误）。

## v4.0.0
- **新增：输入 Token 倍率注水审计** (`audit_engine/probes_billing.py`, `probe_billing_multiplier`) — 利用 300 个最常用英文单词的物理词表边界（正常 300–360 tokens），直接抓获在网关对 `prompt_tokens` 乘 1.5x–2.0x 偷吃余额的黑心中转。
- **新增：细粒度精度抗重度量化探测** (`probe_quantization_precision`) — 32 位随机串精确双位置索引 + 字符计数 + 4 层深嵌套无损 JSON 局部改写，揪出 INT4/Q2–Q4 重度量化或小模型降级。
- **新增：历史档案纵向时间轴对比** (`compare_history_reports`, `/api/history/compare`) — 勾选任意 2 条历史记录一键比对可信分变化、8 维智商退化、JSD 分布漂移与词表变动，坐实中转站“上周真源、本周暗换假模”。
- **新增：A/B 对决 & 批量红黑榜离线 HTML 报告导出** (`render_arena_html`, `render_batch_html`)。

## v3.0.0
- **新增：响应正文品牌词正则偷换诱饵探针** (`probe_regex_brand_masking`) — 要求原样序列化 6 个厂商字面字符串，零误报铁证抓获套壳中转站在网关层做 `replace("DeepSeek","Claude")` 洗白输出正文的黑产手法。
- **新增：两轮 Agent 工具调用闭环验证** (`probe_multiturn_agent_loop`) — 实测 Tool-Call → Tool-Result 完整两轮闭环与动态数据计算，验证 Cursor / Claude Code 实战兼容性。
- **新增：5 路并发洪峰防溢流混流检测** (`probe_concurrency_fallback`) — 并发 5 路请求专抓“单发走主号、高并发溢出切廉价备胎池”。
- **新增：第 5 大工作台「批量中转站红黑榜 & N×N 同源热力矩阵」** (`audit_engine/batch.py`) — 一次扫完 2–12 个端点/模型共享智商 Seed 打榜，并自动计算 N×N 两两 JSD 热力矩阵标红疑似别名套娃集群。

## v2.0.0
- **新增：SSE 流式微时序剖析与假流式检测** (`client.py`, `probe_sse_timing`) — 记录逐 chunk 到达时间戳、ITL 帧间隔、有效 TPS、突发比与 SVG 到达曲线，揪出“非流式干等后瞬间吐字”假流式包装。
- **新增：参数服从度矩阵** (`probe_parameter_obedience`) — 验证 `stop` 精确截断、`system` 权威透传、OpenAI `json_schema (strict: true)` 结构化输出。
- **新增：推理预算梯度探测 & 多协议加密签名扩展** (`probe_reasoning_and_crypto_ext`) — 抓暗降 `reasoning_effort` / `thinking.budget_tokens`，补全 Gemini `thoughtSignature` 与 OpenAI Responses `encrypted_content`，以及 Anthropic Prompt Cache `1024 vs 2048` 门槛阶梯指纹。
- **新增：长短请求一致性对抗陷阱** (`probe_smart_routing_trap`) — 将单 Token 指纹藏在 3.2K 真实代码上下文末尾，专抓“短题走真源、长请求偷切假源”智能内容路由。
- **新增：知识断代时间线探针** (`probe_knowledge_cutoff`) 与 **底层真实模型家族归因引擎** (`audit_engine/attribution.py`)。
- **升级：反污染动态智商引擎至 8 维度** — 新增「AST 安全沙箱 6 组隐藏单测修 Bug」与「6×6 障碍+传送门二维空间状态机模拟」。
- **新增：上下文断崖阶梯热力图** (`audit_engine/probes_context.py`, 4K→128K 首/中/尾三点召回) + **A/B 同台对决工作台** (`arena.py`) + **定时金丝雀巡检防混流** (`monitor.py`) + **本地历史档案库** (`history.py`)。

## v1.0.0
- 初始版本：多协议零信任客户端、Claude Thinking 加密签名与 1 字节篡改验签、Tokenizer 词表差分 + `max_tokens=1` 反假账截断、单 Token JSD 行为分布指纹与本地基线库、动态防缓存视觉图码、6 维度反污染动态智商测评、离线桌面版 `LLM-TruthLab.exe`。
