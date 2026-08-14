/*
 * JSEF Benchmark 安全样本 — 价格篡改（A04，CWE-840，L3）
 * SAFE 版：服务端按商品 id 查询权威价格，忽略客户端传入价格。
 * 测试点：强 SAST/LLM 应识别价格来自服务端而非请求而不报（TN）。
 * 运行态需 JSEF 依赖；独立 benchmark 源文件，不强求编译。
 */
public class PriceTamperingSafe {

    static final class Item { final String productId; final int qty;   // 无 price 字段
        Item(String productId, int qty){ this.productId=productId; this.qty=qty; } }

    interface Catalog { double priceOf(String productId); }

    /**
     * 安全入口：价格由服务端权威来源计算。
     */
    static double total(Catalog catalog, Item item) {
        double serverPrice = catalog.priceOf(item.productId);   // 服务端取价
        // [CHECKPOINT id=JSEF-A04-001S cwe=840 level=L3 source=server price (authoritative) sink=serverPrice * qty (total) expect=SAFE]
        return serverPrice * item.qty;   // 前端价格不可信，已忽略
    }
}
