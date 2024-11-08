package com.freedom.securitysamples.cve;



//POC地址：https://github.com/X1r0z/spring-amqp-deserialization
//CVE-2023-34050是一个Spring AMQP反序列化漏洞，影响的版本包括1.0.0到2.4.16和3.0.0到3.0.9[1][5]。这个漏洞主要是由于SimpleMessageConverter或SerializerMessageConverter默认未配置白名单，导致可以反序列化任意类[2]。如果应用程序使用了SimpleMessageConverter或SerializerMessageConverter，并且用户没有配置允许列表模式，那么这个应用程序就可能受到这个漏洞的影响[5]。
//
//        关于漏洞的触发条件，主要有以下几点[3][5]：
//        1. 使用了SimpleMessageConverter或SerializerMessageConverter。
//        2. 用户未配置允许列表模式。
//        3. 不受信任的消息源获得了向RabbitMQ broker写消息的权限，从而发送恶意内容。
public class CVE202334050 {
    public static void main(String[] argv){

    }
}
