# 计划 03：基于 Spring Boot 漏洞第一性原理的「框架机制」原子级样本集

> 目标：从近期 Spring Boot 0day/1day 中抽象出**与 Spring Boot 无关**的原子原理范式，
> 构造符合 MECE 原则的复杂漏洞样本（vuln + sec 对照），用于评估大模型 / harness
> 对「同类原理」漏洞的检测能力。样本用 Java 标准库语义**自包含**复现，
> **不出现 Spring / Tomcat / WebFlux 等具体框架类名**（与现有 `JSEF-S4S-*`、
> `JSEF-SPEL-*` 等绑定 Spring 语义的样本刻意区分）。

---

## 0. 背景：Spring Boot 漏洞的第一性原理抽象

### 0.1 近期 Spring Boot 0day/1day 事实（公开来源，仅作抽象依据）

| 真实漏洞 | 机制（已公开确认） |
|---|---|
| Spring4Shell CVE-2022-22965 | DataBinder 支持嵌套属性绑定 `class.module.classLoader.resources...`，攻击者可写 Tomcat AccessLogValve 属性实现写文件/RCE。核心 = **数据绑定机制允许污点穿越到内部危险对象**。 |
| Spring Cloud Gateway SpEL CVE-2022-22947 / CVE-2025-41243 | actuator 端点接受用户定义的 route，其 predicate/filter 表达式被 SpEL 求值引擎执行 → RCE。核心 = **不可信的配置/路由定义被动态求值（eval）**。 |
| Actuator 暴露类（env/heapdump/refresh） | 高权限运维端点未鉴权暴露，接受不可信输入触发危险动作（配置篡改、信息泄露）。核心 = **信任边界内的高权限端点未授权 + 不可信写**。 |
| Spring Security 鉴权绕过类 CVE | 授权决策依赖可被攻击者影响的条件（特定字段/header/URL 形态），导致 `AuthorizationDecision` 被短路跳过。核心 = **授权判断被可绕过条件短路**。 |

### 0.2 跨框架的不变原子范式（去 Spring 化）

上述漏洞共享的、与具体框架无关的底层危险组合：

- **SB-P1（Binder Traversal）** = 通用「按字符串路径自动调用嵌套 setter/getter」机制，污点可穿越到内部危险对象（class → classLoader → resources），再写其危险属性。任何 ORM/Web 绑定/配置映射器都有同类风险。
- **SB-P2（Config-as-Expression）** = 声明式/持久化的配置（route/规则/模板）中含有表达式且被求值引擎执行，攻击者控制该配置内容 → eval 即代码。任何「配置即代码」系统（规则引擎、网关、低代码）都有同类风险。
- **SB-P3（Privileged Endpoint Exposure）** = 高权限管理端点未做鉴权边界，且接受不可信输入触发危险动作（写文件/改状态）。任何「管理面暴露」设计都有同类风险。
- **SB-P4（AuthZ Bypass by Short-circuit）** = 授权决策依赖可被攻击者操纵的输入条件，使 `deny/allow` 判断被短路跳过。任何「基于条件/上下文的授权」都有同类风险。

### 0.3 MECE 拆分（4 个互不重叠的原子范式维度）

按「框架机制的**种类**」切分，相互独立：

- **SBM-1 Binder Traversal（反射式属性绑定穿越）** — 对应 Spring4Shell，但纯标准库自包含
- **SBM-2 Config-as-Expression（声明式配置被动态求值）** — 对应 Gateway SpEL（存储型/声明式 eval，与现有 L0 SpEL「直输即 eval」区分）
- **SBM-3 Privileged Endpoint Exposure（高权限端点暴露+不可信写）** — 对应 Actuator 暴露类
- **SBM-4 AuthZ Bypass by Short-circuit（授权短路绕过）** — 对应 Spring Security 鉴权绕过类

> 与现有样本的关系：现有 `JSEF-S4S-*` 绑定 Spring `@ModelAttribute` 语义、`JSEF-SPEL-*` 是「用户输入直传 eval」。本计划刻意**不**重复这些，而是抽象到更底层的通用机制，用标准库自包含复现，新名字空间 `JSEF-SBM-` 避免混淆。

---

## 1. 样本设计规范（遵守仓库门禁，见 AGENTS.md）

每个 vuln 样本：
- 路径：`benchmark/cases/vuln/sbm/SBM{i}_{Scenario}.java`，包 `com.jsef.benchmark.vuln.sbm`
- 污点流 source→sink 清晰可读，保留 `// [VULN]` 行内注释
- sink 行上方加 `// [CHECKPOINT id=JSEF-SBM-xxx cwe=<CWE> level=Lx source=<源> sink=<终点> expect=VULN]`（L3+ 带 trace=，节点必须真实存在）
- sec 对照：`benchmark/cases/sec/sbm/SBM{i}_{Scenario}_Safe.java`，`expect=SAFE` + CSV 行

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

## 2. 样本清单（4 维度 × 分级，建议 12 vuln + 12 sec）

### 维度 SBM-1 Binder Traversal（CWE-94，对应 Spring4Shell）
- `JSEF-SBM-101` L3：通用「属性绑定器」按 `a.b.c` 路径自动 `getX().setY()` 穿越，污点名 `class.module.classLoader` 被解析到 ClassLoader 并 `setXxx` 写其危险属性。带 trace（穿越节点）。
- `JSEF-SBM-102` L5（gadget chain）：绑定穿越到内部对象后，最终 `getResources().getContext()...setPattern()` 写日志路径 → 文件写 sink（抽象为 `Files.write`，占位）。带 trace（跨节点链）。
- `JSEF-SBM-101S/102S` sec：绑定器维护 disallowedFields 黑名单（class/module/classLoader 前缀），拒绝穿越。

### 维度 SBM-2 Config-as-Expression（CWE-917，对应 Gateway SpEL）
- `JSEF-SBM-201` L2：route/规则定义存库后由「表达式求值器」执行，定义内容来自不可信 POST，求值器 `eval(definition)` 触发命令。
- `JSEF-SBM-202` L4（跨文件）：route 定义经「存储→读取→求值」三阶段，定义在文件 A 写入、文件 C 求值器执行（仿 longtask 跨文件）。带 trace。
- `JSEF-SBM-201S/202S` sec：配置中的表达式在「白名单上下文」求值（仅允许安全函数，禁用 `#runtime`/`T()` 类引用），或改为静态配置。

### 维度 SBM-3 Privileged Endpoint Exposure（CWE-749/22，对应 Actuator 暴露）
- `JSEF-SBM-301` L2：管理端点 `admin/updateConfig` 未鉴权，接受不可信 `path`+`content` 直接 `Files.write(path, content)`。sink=文件写。
- `JSEF-SBM-302` L4：端点暴露管理 API，接受不可信 `beanName` 触发 `getBean(beanName).refresh()` 危险重载（抽象 refresh 为危险动作）。带 trace。
- `JSEF-SBM-301S/302S` sec：端点加鉴权校验（调用方身份/角色），且路径限死在白名单目录。

### 维度 SBM-4 AuthZ Bypass by Short-circuit（CWE-862，对应 Security 鉴权绕过）
- `JSEF-SBM-401` L2：授权方法 `isAuthorized(req)` 先判 `req.role=="admin"` 再判 `req.override!=null`（override 由用户控制）→ 短路放行。
- `JSEF-SBM-402` L4：授权依赖「请求头 X-Internal-Secret」或「特定 URL 前缀」可被攻击者伪造，导致 `decide()` 返回 ALLOW。带 trace（跨方法）。
- `JSEF-SBM-401S/402S` sec：授权不依赖用户可控字段，采用服务端强制的权限矩阵。

---

## 3. 实施步骤（按 phase 推进，每 phase 后门禁校验）

### Phase A — SBM-1 + SBM-2（Binder 穿越 + 配置求值）
1. 写 `SBM1_BinderTraversal.java`、`SBM2_ConfigExpression.java` 及 `_Safe.java`（含 L5/L4 跨文件）。
2. 加 CHECKPOINT（精确 sink 行，L3/L4/L5 带 trace）。
3. 追加 CSV 行，跑 `validate_checkpoints.py` 退出码 0。

### Phase B — SBM-3 + SBM-4（端点暴露 + 授权绕过）
1. 写 `SBM3_PrivilegedEndpoint.java`、`SBM4_AuthzBypass.java` 及 `_Safe.java`。
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
- [ ] 样本**未出现** spring / tomcat / webflux / ModelAttribute 等框架名（纯标准库自包含）

## 5. 反模式守卫（NOT to do）

- 不要写 `org.springframework.*` / `tomcat` / `WebFlux` 真实依赖或调用（污染「原子级」抽象目标）。
- 不要与现有 `JSEF-S4S-*`、`JSEF-SPEL-*`、`JSEF-ACTUATOR-*` 样本重复或冲突（新名字空间 JSEF-SBM-）。
- 不要发明不存在的 Java API；用 `Method.invoke`/`Class.getMethod`/`Files.write`/`ScriptEngine`(javax.script 标准) 等。
- 不要跳过 `validate_checkpoints.py` 就交付；行号漂移即门禁失败。
- L1/L2 样本不加 `trace=`（AGENTS.md：单点直连 L0–L2 不加）。
