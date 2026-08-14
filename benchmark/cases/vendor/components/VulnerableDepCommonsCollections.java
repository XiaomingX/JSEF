package com.jsef.benchmark.vendor.components;

/**
 * JSEF Benchmark — A06 易受攻击组件（CWE-1104，L2）
 *
 * 场景：引入 commons-collections 3.2.1（CVE-2015-7501）。该版本在反序列化
 * 链中 InvokerTransformer 可被用于执行任意命令（与 CWE-502 反序列化配合
 * 构成经典 gadget chain）。
 *
 * 为何危险：过时组件携带已知可利用 gadget，是供应链层面的"预置炸药"，
 * 即便业务代码未直接调用，反序列化入口即可触发。
 *
 * 安全底线：仅 localhost 演示语义，不写真实 gadget chain 利用脚本。
 *
 * 单文件双 checkpoint：VULN 行声明 3.2.1，SAFE 行声明已移除/升级版本。
 * 配套 pom 片段见 pom_commons_collections.xml。
 */
public class VulnerableDepCommonsCollections {

    /**
     * VULN：引入存在 CVE-2015-7501 的 commons-collections 3.2.1。
     */
    // [CHECKPOINT id=JSEF-A06-002 cwe=1104 level=L2 source=pom.xml / build config sink=dependency:commons-collections:commons-collections:3.2.1 (CVE-2015-7501) expect=VULN]
    static final String COMMONS_COLLECTIONS_VERSION = "3.2.1";

    /**
     * SAFE：升级到修复版 3.2.2（或迁移到 4.x 并移除危险 transformer）。
     */
    // [CHECKPOINT id=JSEF-A06-002S cwe=1104 level=L2 source=pom.xml / build config sink=dependency:commons-collections:commons-collections:3.2.2 (CVE-2015-7501 fixed) expect=SAFE]
    static final String COMMONS_COLLECTIONS_VERSION_SAFE = "3.2.2";

    public static void main(String[] args) {
        System.out.println("[demo] commons-collections resolved version = " + COMMONS_COLLECTIONS_VERSION
                + " (should be 3.2.2+ in production)");
    }
}
