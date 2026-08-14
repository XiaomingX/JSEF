/*
 * JSEF Benchmark 样本 — 价格篡改（A04，CWE-840，L3）
 * 运行态需 JSEF 依赖（Spring MVC）；独立 benchmark 源文件，不强求编译。
 * 安全底线：仅 localhost 演示语义，不写真实支付绕过利用。
 *
 * 知识点（A04 不安全设计，CWE-840 业务逻辑错误）：
 *   服务端直接使用客户端提交的单价计算总价，攻击者篡改前端价格字段即可低价下单。
 *   正确设计应由服务端按商品 id 查询权威价格。此处"数据流干净但设计缺失"：价格来自不可信前端。
 */
public class PriceTampering {

    static final class Item { final String productId; final double price; final int qty;
        Item(String productId, double price, int qty){ this.productId=productId; this.price=price; this.qty=qty; } }

    /**
     * 危险入口：直接使用前端传入的单价算总价。
     */
    static double total(Item item) {
        // source：不可信 price（HTTP 请求体，攻击者可控）
        // [CHECKPOINT id=JSEF-A04-001 cwe=840 level=L3 source=request-bound price sink=price * qty (total) expect=VULN]
        return item.price * item.qty;   // 越权：篡改 price 即改总价
    }
}
