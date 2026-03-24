# JSEF Skills Specification

## 🛠️ Skill 1: generate_vuln_case (生成新漏洞案例)
**描述**：创建一个完整的漏洞教学模块，包含不安全代码、安全代码和利用方式。
**触发词**：`/new-case [漏洞类型] [业务场景]`
**执行步骤**：
1. **设计场景**：构思一个符合业务逻辑的场景（例如：基于 Cookie 的越权查看订单）。
2. **编写不安全代码 (Vulnerable Controller/Service)**：
   - 展示错误的编码习惯（如拼接 SQL、信任前端输入）。
   - 添加详细注释：`// [VULN] 漏洞点：直接使用了用户输入的ID`。
3. **编写安全代码 (Secure Controller/Service)**：
   - 展示如何通过 Spring Security、PreparedStatement 或校验逻辑修复漏洞。
   - 对比差异点。
4. **生成 Payload**：提供 `curl` 命令或 HTTP 请求包用于复现。

## ⚡ Skill 2: optimize_springboot (优化现有代码)
**描述**：按照 Spring Boot 3.x 和 Java 17+ 标准重构代码。
**触发词**：`/optimize [文件名/代码段]`
**执行逻辑**：
1. **依赖检查**：检查是否使用了过时的注解或依赖（如替换 `RestTemplate` 为 `WebClient`，或优化 Lombok 使用）。
2. **语法升级**：应用 Java 17+ 新特性（Records, Switch Expressions, Text Blocks）。
3. **结构优化**：确保 Controller-Service-Repository 分层清晰，异常处理全局化 (`@ControllerAdvice`)。

## 📝 Skill 3: write_security_docs (编写教学文档)
**描述**：为特定漏洞案例生成 Markdown 格式的教学文档。
**触发词**：`/doc [漏洞名称]`
**输出模板**：
- **漏洞原理**：简述漏洞成因。
- **攻击场景**：攻击者如何利用该漏洞。
- **核心代码对比**：
  - ❌ 错误写法（高亮关键行）
  - ✅ 正确写法（高亮修复行）
- **复现步骤**：Step-by-step 指南。
- **实战作业**：留给学生的思考题。

## 🧪 Skill 4: generate_test_case (生成安全测试用例)
**描述**：使用 JUnit 5 和 MockMvc 编写单元测试，验证漏洞的存在与修复。
**触发词**：`/test [Controller名称]`
**执行逻辑**：
1. 编写 `shouldSucceedWithMaliciousPayload()` 测试用例以验证漏洞存在（预期攻击成功）。
2. 编写 `shouldFailWithMaliciousPayload()` 测试用例以验证安全代码（预期攻击被拦截）。