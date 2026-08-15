# JSEF Benchmark 样本统计报告

> 数据来源：`benchmark/expectedresults.csv`（事实源，与源码 `// [CHECKPOINT]` 标注双向一致）
> 生成方式：`validate_checkpoints.py` 退出码 0（无孤儿/重复/行号漂移，trace 节点 0 无效）
> 统计时点：本文件生成时 CSV 共 **503 个 checkpoint（含表头 504 行）**

---

## 1. 总览

| 指标 | 数值 |
|------|------|
| 机器可读 checkpoint 总数 | **503** |
| VULN（应报） | **268** |
| SAFE（不应报，算 TN/FP） | **235** |
| 区分度级别 | L0 / L1 / L2 / L3 / L4 / L5（全梯度） |
| CWE 覆盖数（仅 VULN） | **69** |
| category（slug）覆盖数 | **121** |
| 带 `trace=` 路径节点的样本 | **65** |

---

## 2. 区分度级别分布（L0–L5）

| 级别 | 数量 | 含义 |
|------|------|------|
| L0 | 18 | 能力基准（显式直连，所有工具/模型应命中） |
| L1 | 139 | 单跳直连 |
| L2 | 106 | 多跳（变量无断点） |
| L3 | 115 | 间接 / 跨方法 |
| L4 | 86 | 跨文件 / 框架语义 / 状态机 |
| L5 | 39 | gadget chain |
| **合计** | **504** | 含表头 |

---

## 3. 样本族分布（按 id 前缀）

| 样本族 | 数量 | 说明 |
|--------|------|------|
| 基础 / OWASP Top 10 | 382 | 教学对比 + 梯度样本（含 vendor 抽象） |
| 长程任务（LT 系列） | 16 | 跨文件追踪 / 框架状态机 / gadget 还原 / 多跳拼接 / 版本门控 |
| 代码质量 / 性能 DoS（PERF 系列） | 15 | 慢 SQL / 资源泄漏 / 持锁 sleep / 循环大对象 / ReDoS 注入版 |
| LGTM 缺口（TB/REFLECT/FMT/HOST/XSLT/FWD/SEED） | 14 | 信任边界 / 反射注入 / 格式串 / hostname / XSLT / forward / 种子 |
| 逻辑漏洞（PAY/MEM/WF 系列） | 12 | 支付篡改 / 优惠券复用 / 会员等级篡改 / 邀请刷奖 / 重复退款 / 步骤跳过 |
| **原子范式样本族（TCM/SBM/DBG/STR）** | **64** | 从 Fastjson/Spring Boot/Dubbo/Struts2 抽象的去库化原子危险范式，纯标准库自包含 |

---

## 4. CWE 覆盖（VULN 仅计，Top 12）

| CWE | 数量 | 类别 |
|-----|------|------|
| 917 表达式语言注入 | 25 | spel/ognl/groovy/mvel/beanshell/script/template/thymeleaf/freemarker/el-injection |
| 502 不安全反序列化 | 21 | deserialization / fastjson / jackson / yaml / unsafe-deserialization |
| 89 SQL 注入 | 17 | sql-injection(及 jdbc/jpa/mybatis/postgres 变体) |
| 78 命令注入 | 12 | command-injection |
| 285 授权失效 | 10 | authorization-bypass / broken-access-control / priv-esc / idor |
| 798 硬编码凭证/密钥 | 7 | hardcoded-credentials / hardcoded-key / hardcoded-key-ecb |
| 840 业务逻辑 | 7 | business-logic / race-condition / mass-assignment |
| 918 SSRF | 6 | ssrf |
| 639 IDOR | 6 | idor / idor-broken-access-control |
| 22 路径穿越 | 5 | path-traversal / zip-slip |
| 1333 ReDoS | 5 | redos / regex-dos |
| 400 性能 DoS | 5 | slow-sql / perf-anti-pattern |

> 全量覆盖 **69 个 CWE**，含 OWASP Top 10 2021 全部十类。

---

## 5. 路径正确性评测（`trace=`）

- 共 **65** 条样本携带 `trace=` 路径节点（L3+ 跨节点样本），覆盖跨方法 / 跨文件 / gadget chain。
- 可用 `scorecard.py --check-trace` 量化 `trace_recall` / `trace_precision`。
- 节点格式：`file:line` 相对仓库根路径，全部指向真实存在的源码行（validate 仅告警不阻断，当前 0 无效）。

---

## 6. 门禁状态

- `validate_checkpoints.py`：**退出码 0**，双向一致，无孤儿 CSV 行 / 孤儿源码注解 / 重复 id / 行号漂移。
- `scorecard.py`：双源可关联，支持 Recall / Precision / F1 / MCC / Youden / 时延 / 定位精度 / 能力完备度交叉矩阵。

---

## 7. 与历史版本对比

| 维度 | 早期版本 | 当前版本 |
|------|----------|----------|
| checkpoint 总数 | 133 | **503** |
| CWE 覆盖 | 34 | **69** |
| 区分度 | L1–L5（无 L0） | **L0–L5 全梯度** |
| 长程任务样本 | 无 | **LT 系列 16** |
| 代码质量/性能 DoS | 少量（redos 等） | **PERF 系列 15 + LGTM 缺口 14** |
| 逻辑漏洞样本 | 通用越权/IDOR（无支付/会员/流程） | **PAY/MEM/WF 系列 12** |
| 原子范式样本族 | 无 | **TCM/SBM/DBG/STR 系列 64** |
| trace 路径评测 | 无 | **65 条带 trace** |

> 注：本报告数字与 `benchmark/README.md` §3、仓库根 `README*.md`「当前样本规模」段保持一致，均由 `expectedresults.csv` 实查生成。
