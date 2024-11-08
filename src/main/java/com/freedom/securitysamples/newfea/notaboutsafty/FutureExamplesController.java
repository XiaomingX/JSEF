package com.freedom.securitysamples.newfea.notaboutsafty;

import org.springframework.beans.BeanUtils;
import org.springframework.scheduling.annotation.Async;
import org.springframework.scheduling.annotation.EnableAsync;
import org.springframework.scheduling.annotation.AsyncResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.util.concurrent.ListenableFuture;

import java.util.List;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@RestController
@RequestMapping("/api/future-examples")
@EnableAsync
public class FutureExamplesController {
    private static final int DEFAULT_TIMEOUT = 30;

    @GetMapping("/future-example")
    @Async
    public Future<String> getFuture() {
        return new AsyncResult<>("Hello from Future");
    }

    @GetMapping("/completable-future-example")
    @Async
    public CompletableFuture<String> getCompletableFuture() {
        return CompletableFuture.supplyAsync(() -> "Hello from CompletableFuture");
    }

    @GetMapping("/listenable-future-example")
    @Async
    public ListenableFuture<String> getListenableFuture() {
        return new AsyncResult<>("Hello from ListenableFuture");
    }

    @GetMapping("/test-all")
    public String test() throws ExecutionException, InterruptedException {
        Future<String> future = getFuture();
        CompletableFuture<String> completableFuture = getCompletableFuture();
        ListenableFuture<String> listenableFuture = getListenableFuture();

        return "Future: " + future.get() + ", CompletableFuture: " + completableFuture.get() + ", ListenableFuture: " + listenableFuture.get();
    }

    @GetMapping("/bean-utils-example")
    public String beanUtilsExample() {
        SourceObject source = new SourceObject("John Doe", DEFAULT_TIMEOUT);
        TargetObject target = new TargetObject();
        BeanUtils.copyProperties(source, target);
        return "Copied properties: " + target;
    }

    @GetMapping("/radix-tree-example")
    public String radixTreeExample() {
        // This is a simple example showcasing Radix Tree usage.
        RadixTree radixTree = new RadixTree();
        radixTree.insert("hello", "Hello World");
        radixTree.insert("hi", "Hi there");
        String result = radixTree.search("hello");
        return "Radix Tree result: " + result;
    }

    @GetMapping("/zero-copy-example")
    public String zeroCopyExample() {
        // This is a simple demonstration of Zero Copy technique.
        String data = "This is a large data that we need to transfer efficiently.";
        byte[] byteArray = data.getBytes();
        return new String(byteArray, 0, byteArray.length);
    }

    @GetMapping("/stream-api-enhancement")
    public String streamApiEnhancement() {
        List<String> names = List.of("Alice", "Bob", "Charlie", "David");
        String result = names.stream()
                .filter(name -> name.startsWith("A"))
                .map(String::toUpperCase)
                .collect(Collectors.joining(", "));
        return "Stream API result: " + result;
    }

    @GetMapping("/switch-expression-enhancement")
    public String switchExpressionEnhancement() {
        String day = "MONDAY";
        String result = switch (day) {
            case "MONDAY", "FRIDAY", "SUNDAY" -> "Weekend or Start of Week";
            case "TUESDAY", "WEDNESDAY", "THURSDAY" -> "Midweek";
            default -> "Invalid day";
        };
        return "Switch Expression result: " + result;
    }

    @GetMapping("/optional-enhancement")
    public String optionalEnhancement() {
        Optional<String> optional = Optional.of("Hello Optional");
        String result = optional.orElseThrow(() -> new IllegalArgumentException("Value not present"));
        return "Optional result: " + result;
    }

    @GetMapping("/instanceof-enhancement")
    public String instanceofEnhancement() {
        Object obj = "This is a string";
        if (obj instanceof String str) {
            return "Instanceof result: " + str.toUpperCase();
        } else {
            return "Instanceof result: Not a string";
        }
    }

    @GetMapping("/stream-example")
    public String streamExample() {
        Stream<Integer> numbers = Stream.of(1, 2, 3, 4, 5);
        int sum = numbers.filter(n -> n % 2 == 0).mapToInt(Integer::intValue).sum();
        return "Stream example result: " + sum;
    }

    static class SourceObject {
        private String name;
        private int age;

        public SourceObject(String name, int age) {
            this.name = name;
            this.age = age;
        }

        // Getters and setters
        public String getName() {
            return name;
        }

        public void setName(String name) {
            this.name = name;
        }

        public int getAge() {
            return age;
        }

        public void setAge(int age) {
            this.age = age;
        }
    }

    static class TargetObject {
        private String name;
        private int age;

        // Getters and setters
        public String getName() {
            return name;
        }

        public void setName(String name) {
            this.name = name;
        }

        public int getAge() {
            return age;
        }

        public void setAge(int age) {
            this.age = age;
        }

        @Override
        public String toString() {
            return "TargetObject{name='" + name + "', age=" + age + "}";
        }
    }

    static class RadixTree {
        // Simplified Radix Tree implementation
        private final Node root = new Node();

        static class Node {
            String key;
            String value;
            Node[] children = new Node[26];
        }

        public void insert(String key, String value) {
            Node current = root;
            for (char c : key.toCharArray()) {
                int index = c - 'a';
                if (current.children[index] == null) {
                    current.children[index] = new Node();
                }
                current = current.children[index];
            }
            current.key = key;
            current.value = value;
        }

        public String search(String key) {
            Node current = root;
            for (char c : key.toCharArray()) {
                int index = c - 'a';
                if (current.children[index] == null) {
                    return null;
                }
                current = current.children[index];
            }
            return current.value;
        }
    }
}
