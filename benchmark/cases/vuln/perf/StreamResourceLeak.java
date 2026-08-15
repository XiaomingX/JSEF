package com.jsef.benchmark.vuln.perf;

import java.io.FileInputStream;
import java.io.IOException;

/**
 * JSEF-Benchmark A1「代码质量/性能 DoS」— 流资源泄漏（L1 单跳）
 *
 * 长程/质量子目标清单：
 *   ① 识别不可信/外部路径 path 进入文件读取；
 *   ② 识别 new FileInputStream(path) 手动打开后未在 finally 关闭；
 *   ③ 识别异常路径下流未关闭，文件句柄泄漏 → fd 耗尽导致服务 DoS；
 *   ④ 区分 CWE-772（资源未关闭）与 CWE-400（资源耗尽）语义。
 *
 * 可达性说明：
 *   source = path（方法入参，类比 @RequestParam path），直接到达
 *   sink = new FileInputStream(path) 资源占用点，单跳直连，L1。
 *
 * 安全底线声明：
 *   仅 localhost 教学演示，不提供真实 fd 耗尽攻击脚本，不针对真实文件服务。
 *
 * 修复要点（对照 StreamResourceLeak_Safe.java）：
 *   使用 try-with-resources 自动关闭 InputStream。
 *
 * CWE-772 / CWE-404（资源泄漏 / 不当释放）。
 */
public class StreamResourceLeak {

    /**
     * L1 单跳：手动打开文件流后未关闭。
     *
     * @param path 外部传入路径（类比 @RequestParam path）
     */
    public void read(String path) throws IOException {
        FileInputStream in = new FileInputStream(path);
        int b = in.read(); // 读取首字节仅作演示
        // [CHECKPOINT id=JSEF-PERF-IO-001 cwe=772 level=L1 source=path sink=new FileInputStream expect=VULN]
        // 缺陷：in 未关闭，异常时直接泄漏文件句柄，fd 耗尽导致 DoS
    }

    public static void main(String[] args) throws IOException {
        new StreamResourceLeak().read("/tmp/localhost-demo.txt");
    }
}
