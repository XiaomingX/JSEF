# 计划 02：基于 Fastjson 漏洞第一性原理的「类型混淆机制」原子级样本集

> 目标：从近期 Fastjson 0day/1day 中抽象出**与 Fastjson 无关**的原子原理范式，
> 构造符合 MECE 原则的复杂漏洞样本（vuln + sec 对照），用于评估大模型 / harness
> 对「同类原理」漏洞的检测能力。样本必须用 Java 标准库语义**自包含**复现，
> 不出现 fastjson 类名、不依赖 fastjson 依赖。

---

## 0. 背景：Fastjson 漏洞的第一性原理抽象

### 0.1 近期 Fastjson 0day/1day 事实（公开来源，仅作抽象依据）

| 真实漏洞 | 机制（已公开确认） |
|---|---|
| fastjson 1.2.68 autotype bypass | `checkAutoType(typeName, expectClass)` 中，当 `expectClass` 为白名单父类（如 `AutoCloseable`/`Throwable`/`Runnable`/`Readable`）时，只要 payload 类是其子类即可绕过黑名单；再借 `setter`/`getter`/`close()` 触发 JNDI/RCE。 |
| fastjson ≤1.2.80 (CVE-2022-25845) | 未指定目标类型时 `JSON.parse`/`parseObject` 仍可经 `Throwable` 等父类分支实例化受限 gadget 类。 |
| fastjson 2.x ≤2.0.62 0day | autotype/safeMode 在 `JSONReader`、反序列化器缓存、二次解析路径上被绕过，@type 类仍被实例化并自动调用隐式方法。 |
| `SupportNonPublicField` / `enableDefaultTyping` | 允许控制私有字段或按类型名反序列化任意类。 |

### 0.2 跨库的不变原子范式（去 Fastjson 化）

所有上述漏洞共享同一个「与具体库无关」的危险组合：

> **P0 = 攻击者控制类型/类名 + 系统在对象构造期自动调用隐式方法(构造器/setter/getter/close/readObject/静态块) + 隐式方法链路抵达危险 sink**

这一组合在 Jackson(`enableDefaultTyping`)、XStream、SnakeYAML(`!!`)、
Groovy(`Eval`/方法调用)、Java 原生反序列化、甚至非 Java 生态都成立。
因此样本**不**写 fastjson，而是用标准库语义还原 P0 的各原子技巧。

### 0.3 MECE 拆分（5 个互不重叠的原子范式维度）

为避免重叠，按「攻击者控制类型的**手段**」切分，每个维度相互独立：

- **TCM-1 直接类型选择**（source 直接决定类名 → 反射/类加载实例化）→ 对应「autotype 全局开启」
- **TCM-2 继承关系绕过白名单**（白名单只校验父类，子类污点可控）→ 对应「expectClass 绕过」
- **TCM-3 二次解析/缓存绕过**（首次解析被拦，二次解析/反射缓存跳过校验）→ 对应「2.0.x 缓存/reader 绕过」
- **TCM-4 私有字段可控**（允许写私有字段 → 篡改内部状态触发危险）→ 对应「SupportNonPublicField」
- **TCM-5 属性即代码（隐式方法危险）**（getter/setter/close 非幂等且危险）→ 对应「Tips/JNDI 经 setter 触发」

每个维度含 L1→L5（区分度），且 vuln 与 sec 成对（算 FP/TN）。

---

## 1. 样本设计规范（必须遵守仓库门禁，见 AGENTS.md）

每个 vuln 样本文件：
- 路径：`benchmark/cases/vuln/tcm/TCM{i}_{Scenario}.java`
- 包：`com.jsef.benchmark.vuln.tcm`
- 污点流 source→sink 清晰可读，保留 `// [VULN]` 行内注释
- 在污点到达 sink 的精确行上方加：
  `// [CHECKPOINT id=JSEF-TCM-xxx cwe=502 level=Lx source=<源> sink=<终点> expect=VULN]`
  （L3+ 跨节点样本加 `trace=` 字段，节点必须真实存在）
- sec 对照：`benchmark/cases/sec/tcm/TCM{i}_{Scenario}_Safe.java`，加 `expect=SAFE` checkpoint + CSV 行

CSV 同步追加到 `benchmark/expectedresults.csv`（列序：
`id,cwe,level,type,file,line,source,sink,category,trace`），`type`↔`expect` 对应。

**门禁硬条件**：收尾必须 `validate_checkpoints.py` 退出码为 0。
```bash
python3 benchmark/scripts/validate_checkpoints.py \
  --expected benchmark/expectedresults.csv \
  --cases-dir benchmark/cases \
  --src-dir src/main/java/com/freedom/securitysamples/vulnerability
```

**安全底线**：所有 payload 仅 localhost 演示语义；不写真实利用脚本、不连真实远端、
不提供针对真实目标的 gadget。解释即附修复（sec 文件）。

---

## 2. 样本清单（共 5 维度 × 分级，建议 14 个 vuln + 14 个 sec）

> 复用现有 L4/L5 longtask 风格（见 `benchmark/cases/vuln/longtask/CommonsCollectionsGadget.java`
> 的 gadget-chain 写法、`FastjsonCrossFilePerturbed.java` 的单文件扰动写法）。
> **注意**：本计划样本刻意脱离 Fastjson 类名，名字空间 `JSEF-TCM-` 与现有 `JSEF-FASTJSON-` 区分。

### 维度 TCM-1 直接类型选择（source→类名→反射实例化）
- `JSEF-TCM-101` L1：HTTP 参数直接拼类名 `Class.forName(userInput).getDeclaredConstructor().newInstance()`。sink=反射实例化。
- `JSEF-TCM-102` L3：类型名来自 JSON 字段 `{"cls": userInput}`，经 `ClassLoader.loadClass` 实例化并调用其 `init()`（隐式危险方法）。带 trace。
- `JSEF-TCM-101S/102S` sec：类名取自服务端白名单 Map 常量，用户只传 key。

### 维度 TCM-2 继承关系绕过白名单
- `JSEF-TCM-201` L2：白名单校验 `clazz.getSuperclass()==TrustedBase`，但攻击者传 `Evil extends TrustedBase`，子类 `close()` 调 `Runtime.exec`。sink=AutoCloseable.close→exec。
- `JSEF-TCM-202` L4（跨文件）：`TrustedBase` 在接口层白名单，子类在另一编译单元，经工厂 `create(typeName)` 实例化后 `try-with-resources` 自动调 `close()`。带 trace（跨文件节点）。
- `JSEF-TCM-201S/202S` sec：白名单校验具体类名精确匹配（非父类），禁止子类。

### 维度 TCM-3 二次解析/缓存绕过
- `JSEF-TCM-301` L3：首次 `parse` 经安全校验被拒，但解析结果缓存了 `@type`，二次 `reParse(cached)` 跳过校验直接实例化。带 trace。
- `JSEF-TCM-302` L5（gadget chain）：缓存绕过 + 链末端 `InvokerTransformer` 风格反射调 `Runtime.exec`（复用 `CommonsCollectionsGadget.java:106-121` 的 Function 抽象写法，但**主题改为缓存绕过而非 CC 链**）。
- `JSEF-TCM-301S/302S` sec：每次解析都重新校验，缓存不含类型信息。

### 维度 TCM-4 私有字段可控
- `JSEF-TCM-401` L2：反序列化/字段绑定允许写私有字段 `command`，绑定后 `execute()` 读该字段执行。sink=字段值→exec。
- `JSEF-TCM-402` L4：私有字段为 `ScriptEngine` 引用，setter 注入引擎后 getter 惰性求值触发 `eval(userScript)`。带 trace。
- `JSEF-TCM-401S/402S` sec：私有字段不参与绑定（白名单字段），危险字段 final 只读。

### 维度 TCM-5 属性即代码（隐式方法危险）
- `JSEF-TCM-501` L1：POJO getter 非幂等且危险——`getConfig()` 内部 `InetAddress.getByName(host)`（SSRF）或 `JNDI.lookup(url)`，host/url 来自字段。
- `JSEF-TCM-502` L3：setter `setDataSource(url)` 内部直接 `DataSource` 连接/lookup，URL 不可信。带 trace。
- `JSEF-TCM-503` L5（跨方法 chain）：getter 调用 getter→最终 `JdbcRowSetImpl` 风格 `lookup`（抽象为 `ctx.lookup(url)`）→ 危险。带 trace。
- `JSEF-TCM-501S/502S/503S` sec：getter/setter 不触发副作用，URL 经白名单校验。

---

## 3. 实施步骤（按 phase 推进，每 phase 后门禁校验）

### Phase A — 维度 TCM-1 + TCM-2（L1/L2 直连 + 继承绕过）
1. 写 `benchmark/cases/vuln/tcm/TCM1_DirectTypeSelect.java`、`TCM2_InheritanceBypass.java` 及对应 `_Safe.java`。
2. 加 CHECKPOINT 注解（精确 sink 行）。
3. 追加 6 行到 `expectedresults.csv`（101/101S/102/102S/201/201S，其中 102 带 trace）。
4. 跑 `validate_checkpoints.py`，退出码必须为 0。

### Phase B — 维度 TCM-3 + TCM-4（L3/L4 二次解析/私有字段）
1. 写 TCM3 二次解析（含缓存抽象）、TCM4 私有字段绑定，及 `_Safe.java`。
2. 跨文件样本 TCM-202 拆 A/B/C 三编译单元（仿 `FastjsonCrossFile_A/B/C`）。
3. 追加 CSV 行，跑 validate。

### Phase C — 维度 TCM-5（L1/L3/L5 属性即代码）+ 难度收口
1. 写 TCM5 三个分级样本（含 503 跨方法链），及 `_Safe.java`。
2. 全部追加 CSV，跑 validate（**最终门禁：退出码 0**）。
3. 用 `scorecard.py --expected ... --result <你的结果>` 自测两源关联。

---

## 4. 验证清单（每 phase 必跑）

- [ ] `validate_checkpoints.py` 退出码 0（无孤儿/重复/行号漂移）
- [ ] 每个 vuln 有对应 sec，且 `expect` 与 `type` 一致
- [ ] 所有 `trace=` 节点指向真实存在的 `file:line`（validate 仅告警，但指向无效须修）
- [ ] 污点流 source→sink 在代码中可读、无歧义
- [ ] 安全底线：无真实利用脚本、无真实远端连接、explanation 紧跟修复
- [ ] 样本**未出现** fastjson/ jackson/ xstream 等具体库名（纯标准库语义自包含）

## 5. 反模式守卫（NOT to do）

- 不要写 fastjson 真实依赖或调用 `com.alibaba.fastjson.*`（这会污染「原子级」抽象目标）。
- 不要发明不存在的 Java API；用 `Class.forName`/`getMethod`/`Method.invoke`/`ClassLoader` 等标准库。
- 不要跳过 `validate_checkpoints.py` 就交付；行号漂移即门禁失败。
- 不要把 L1 样本强行加 `trace=`（AGENTS.md：单点直连 L0–L2 不加）。
- 不要与现有 `JSEF-FASTJSON-*`、`JSEF-DESER-*` 样本重复或冲突（新名字空间 JSEF-TCM-）。
