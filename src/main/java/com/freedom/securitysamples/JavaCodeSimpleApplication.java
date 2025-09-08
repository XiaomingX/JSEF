package com.freedom.securitysamples;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.ComponentScan;

@ComponentScan(basePackages = {"com.freedom.securitysamples", "com.litellm"})
@SpringBootApplication(scanBasePackages = "com.freedom.securitysamples")
public class JavaCodeSimpleApplication {

	public static void main(String[] args) {
		SpringApplication.run(JavaCodeSimpleApplication.class, args);
	}

}
