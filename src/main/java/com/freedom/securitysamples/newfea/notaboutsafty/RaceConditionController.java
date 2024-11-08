package com.freedom.securitysamples.newfea.notaboutsafty;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/new")
public class RaceConditionController {

    private int count = 0;

    @GetMapping("/race-condition-demo")
    public String raceConditionDemo() {
        count = 0;

        // 创建两个线程来模拟并发访问共享变量
        Thread t1 = new Thread(() -> {
            for (int i = 0; i < 1000; i++) {
                increment();
            }
        });

        Thread t2 = new Thread(() -> {
            for (int i = 0; i < 1000; i++) {
                increment();
            }
        });

        // 启动两个线程
        t1.start();
        t2.start();

        // 等待线程执行完毕
        try {
            t1.join();
            t2.join();
        } catch (InterruptedException e) {
            e.printStackTrace();
        }

        // 返回结果
        return "Final count: " + count;
    }

    private void increment() {
        count++;
    }
}
