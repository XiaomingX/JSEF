/*
 * JSEF Benchmark 样本 — 业务流程绕过（A01，CWE-840，L4）
 * 运行态需 JSEF 依赖（Spring MVC）；独立 benchmark 源文件，不强求编译。
 * 安全底线：仅 localhost 演示语义，不写真实利用脚本。
 *
 * 知识点（A01 失效访问控制 / 业务逻辑缺陷，CWE-840）：
 *   正常下单流程应为：支付 → 生成订单 → 查询订单。但查询订单接口未校验前置状态（是否支付），
 *   攻击者可跳过支付步骤直接调用查询接口获取订单状态/内容。这是状态机缺失导致的越权访问。
 *   数据流干净，但订单状态机校验缺失，属 A01 与 A04 交叉点。
 */
public class WorkflowBypass {

    static final class Order { final String id; final String status;   // PENDING / PAID
        Order(String id, String status){ this.id=id; this.status=status; } }

    /**
     * 危险入口：查询订单未校验前置支付状态。
     */
    static Order queryOrder(Order order) {
        // source：不可信 orderId（HTTP 参数）；sink：直接返回订单，未校验 status==PAID
        // [CHECKPOINT id=JSEF-A01-004 cwe=840 level=L4 source=request orderId sink=return order (no PAID-state check) expect=VULN]
        return order;   // 越权：未支付订单可被直接查询
    }
}
