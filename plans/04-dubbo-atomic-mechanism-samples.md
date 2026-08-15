# 计划 04：基于 Dubbo 漏洞第一性原理的「RPC 机制」原子级样本集

> 目标：从近期 Apache Dubbo 0day/1day 中抽象出**与 Dubbo 无关**的原子原理范式，
> 构造符合 MECE 原则的复杂漏洞样本（vuln + sec 对照），用于评估大模型 / harness
> 对「同类原理」漏洞的检测能力。样本用 Java 标准库语义**自包含**复现，
> **不出现 Dubbo / Hessian / Triple 等具体框架类名**。
>
> **去重约束（重要）**：仓库已有 `JSEF-REFLECT-001`(CWE-470, 本地 HTTP 参数的类名+方法名→Method.invoke)、
> `JSEF-DESER-*`(直接 ObjectInputStream.readObject)、`JSEF-TCM-*`(类型混淆)。本计划**不**重复这些，
> 只覆盖 Dubbo 漏洞中「现有样本尚未建模」的 3 个独特原子维度，新名字空间 `JSEF-DBG-`。

---

## 0. 背景：Dubbo 漏洞的第一性原理抽象

### 0.1 近期 Dubbo 0day/1day 事实（公开来源，仅作抽象依据）

| 真实漏洞 | 机制（已公开确认） |
|---|---|
| CVE-2021-30179（泛化调用 Generic Invocation） | 客户端不持有服务接口 JAR，可传入任意「类名+方法名+参数」，服务端反射 `Method.invoke` 执行 → RCE。后续补丁加类名黑名单。 |
| CVE-2023-23638 | CVE-2021-30179 的类名黑名单被绕过：通过特定序列化器/协议字段（如启用 JavaNative 反序列化、或配置篡改）使危险反序列化器生效，黑名单过滤形同虚设。本质是「攻击者控制数据解析器/解析格式」+「黑白名单被绕过」。 |
| Dubbo 泛化调用/attachment 注入类 | Provider 信任 Consumer 传入的上下文（attachment/metadata/回调提示），并据此执行危险操作。本质是「跨信任域的隐式信任」。 |

### 0.2 与现有样本的边界（MECE 保证）

- `JSEF-REFLECT-001` 已覆盖「本地 HTTP 参数 → 类名+方法名 → Method.invoke」。**本计划不再写同类本地直连场景**。
- `JSEF-DESER-*` 已覆盖「直接 readObject 反序列化」。**本计划不再写直接反序列化**。
- `JSEF-TCM-*` 已覆盖「类型混淆（直接类型选择 / 继承绕过 / 缓存绕过）」。**DBG-3 仅聚焦「类名黑名单被编码/变形绕过」这一 TCM 未覆盖的子维度**。

### 0.3 跨框架的不变原子范式（去 Dubbo 化）

Dubbo 漏洞中现有样本**未覆盖**的底层危险组合（3 个维度，互不重叠）：

- **DBG-1（Parser/Format Negotiation）** = 请求中携带「用哪种解析器/序列化格式」的指示，攻击者可把它从安全格式切到危险反序列化格式 → 危险反序列化器被启用。任何「数据格式/解析器可由数据自身指定」的协议/网关都有同类风险。
- **DBG-2（Cross-Trust-Boundary Implicit Trust）** = 服务端（Provider）隐式信任来自对端（调用方）的上下文/元数据（attachment/header/回调提示），并据此执行动作。任何「跨进程调用 + 元数据隐式驱动行为」的分布式系统都有同类风险。
- **DBG-3（Deny/Allow-list Bypass by Encoding）** = 类名/类型黑名单靠字符串匹配，攻击者对危险类名做编码/变形（大小写、嵌套包装、转义、双写）绕过匹配。这是「名单绕过」的编码变形子类，TCM-3 是缓存/二次解析绕过，二者不重叠。

---

## 1. 样本设计规范（遵守仓库门禁，见 AGENTS.md）

每个 vuln 样本：
- 路径：`benchmark/cases/vuln/dbg/DBG{i}_{Scenario}.java`，包 `com.jsef.benchmark.vuln.dbg`
- 污点流 source→sink 清晰可读，保留 `// [VULN]` 行内注释
- sink 行上方加 `// [CHECKPOINT id=JSEF-DBG-xxx cwe=<CWE> level=Lx source=<源> sink=<终点> expect=VULN]`（L3+ 带 trace=，节点真实存在）
- sec 对照：`benchmark/cases/sec/dbg/DBG{i}_{Scenario}_Safe.java`，`expect=SAFE` + CSV 行

CSV 追加到 `benchmark/expectedresults.csv`（列序 `id,cwe,level,type,file,line,source,sink,category,trace`）。

**门禁硬条件**：收尾 `validate_checkpoints.py` 退出码 0：
```bash
python3 benchmark/scripts/validate_checkpoints.py \
  --expected benchmark/expectedresults.csv \
  --cases-dir benchmark/cases \
  --src-dir src/main/java/com/freedom/securitysamples/vulnerability
```

**安全底线**：仅 localhost 演示语义；不写真实利用脚本、不连真实远端、不提供针对真实目标的 gadget。解释即附修复（sec 文件）。

---

## 2. 样本清单（3 维度 × 分级，建议 9 vuln + 9 sec）

### 维度 DBG-1 Parser/Format Negotiation（CWE-502，对应 CVE-2023-23638 解析器切换）
- `JSEF-DBG-101` L2：请求体含 `format` 字段，服务端 `if (format.equals("safe")) parseJson(); else deserialize(bytes);` 攻击者可指定危险格式触发 `ObjectInputStream.readObject`。
- `JSEF-DBG-102` L4（跨文件）：format 指示在文件 A 解析、危险解析器在文件 C 装配（仿 longtask 跨文件）。带 trace。
- `JSEF-DBG-101S/102S` sec：解析格式由服务端固定（不读取请求字段），或格式→解析器走白名单且危险格式不在列。

### 维度 DBG-2 Cross-Trust-Boundary Implicit Trust（CWE-440/915，对应 attachment 注入）
- `JSEF-DBG-201` L3：服务端读取对端传入的 `attachment` 中的 `callbackClass` 字段并 `Class.forName(callbackClass).getDeclaredConstructor().newInstance()` 做回调。带 trace。
- `JSEF-DBG-202` L5（跨方法 chain）：attachment 注入 `callbackClass` → 实例化 → 其 `@PostConstruct` 风格 init 调 `Method.invoke(Runtime.exec)`。带 trace（跨节点链）。
- `JSEF-DBG-201S/202S` sec：attachment 中的类名走服务端白名单，或回调实例由服务端预置。

### 维度 DBG-3 Deny/Allow-list Bypass by Encoding（CWE-502/184，对应 CVE-2023-23638 黑名单绕过）
- `JSEF-DBG-301` L3：类名黑名单用 `contains("Runtime")` 字符串匹配，攻击者传入 `rUntime`（大小写/`Ru.n.time` 变形/嵌套包装 `Wrapper$Runtime`）绕过。带 trace。
- `JSEF-DBG-302` L4：黑名单匹配「精确类名」，攻击者用 `ClassLoader.loadClass("java.lang.Run"+"time")` 字符串拼接或 `getClass().forName` 反射拼名绕过。带 trace。
- `JSEF-DBG-301S/302S` sec：用 `Class` 对象精确相等比较（非字符串），且禁用 `ClassLoader` 动态加载。

---

## 3. 实施步骤（按 phase 推进，每 phase 后门禁校验）

### Phase A — DBG-1 + DBG-2（解析器协商 + 跨信任域隐式信任）
1. 写 `DBG1_ParserNegotiation.java`、`DBG2_CrossTrustAttachment.java` 及 `_Safe.java`（含 L4 跨文件 / L5 chain）。
2. 加 CHECKPOINT（精确 sink 行，L3/L4/L5 带 trace）。
3. 追加 CSV 行，跑 `validate_checkpoints.py` 退出码 0。

### Phase B — DBG-3（名单编码绕过）
1. 写 `DBG3_ListBypassByEncoding.java` 及 `_Safe.java`。
2. 追加 CSV 行，跑 validate。

### Phase C — 难度收口
1. 全部追加后跑最终 `validate_checkpoints.py`（退出码 0）。
2. `scorecard.py --expected ... --result <你的结果>` 自测两源关联。

---

## 4. 验证清单（每 phase 必跑）

- [ ] `validate_checkpoints.py` 退出码 0（无孤儿/重复/行号漂移）
- [ ] 每个 vuln 有对应 sec，且 `expect` 与 `type` 一致
- [ ] 所有 `trace=` 节点指向真实存在的 `file:line`
- [ ] 污点流 source→sink 可读、无歧义
- [ ] 安全底线：无真实利用脚本、无真实远端连接、explanation 紧跟修复
- [ ] 样本**未出现** dubbo / hessian / triple 等框架名（纯标准库自包含）
- [ ] 不与 `JSEF-REFLECT-*` / `JSEF-DESER-*` / `JSEF-TCM-*` 维度重复

## 5. 反模式守卫（NOT to do）

- 不要写 `org.apache.dubbo.*` / `hessian` / `tri` 真实依赖或调用。
- 不要重复 `JSEF-REFLECT-001`（本地 HTTP 参数→反射）与 `JSEF-DESER-*`（直接 readObject）的已有场景。
- 不要发明不存在的 Java API；用 `ObjectInputStream` / `ClassLoader` / `Method.invoke` / `Class.forName` 等标准库。
- 不要跳过 `validate_checkpoints.py` 就交付；行号漂移即门禁失败。
- L1/L2 样本不加 `trace=`（AGENTS.md：单点直连 L0–L2 不加）。
