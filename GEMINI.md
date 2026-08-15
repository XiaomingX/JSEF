# GEMINI Project Context: Java Security Education Framework (JSEF)

## Project Overview

This project is the **Java Security Education Framework (JSEF)**, a Spring Boot application designed as a hands-on platform for learning about web security vulnerabilities. It contains over 35 real-world vulnerability examples, allowing developers, students, and security researchers to understand, reproduce, and fix common security flaws.

The core technologies used are **Java 17** and **Spring Boot 3.x**, with **Maven** for dependency management. For ease of use, it runs with an in-memory **H2 database**.

A key architectural convention is the separation of vulnerable and secure code. For each vulnerability type under `src/main/java/com/freedom/securitysamples/vulnerability`, there are two sub-packages:
*   `vuln`: Contains the insecure code that demonstrates the vulnerability.
*   `sec`: Contains the secure, fixed version of the code, often using best practices like parameterized queries, input validation, or proper configuration.

API endpoints follow a consistent pattern:
*   **Insecure:** `/api/v1/{vulnerability-type}/unsafe/{scenario}`
*   **Secure:** `/api/v1/{vulnerability-type}/safe/{scenario}`

The project also includes intentionally vulnerable versions of libraries like `commons-collections`, `xstream`, and `fastjson` to demonstrate deserialization and other dependency-related vulnerabilities.

## Building and Running

You can build and run the project using the following Maven commands:

1.  **Build the project** (skipping tests for speed):
    ```bash
    mvn clean package -DskipTests
    ```

2.  **Run the application**:
    ```bash
    java -jar target/java-sec-code-plus-1.2.0.jar
    ```
    Alternatively, the project can be run via Docker.

Once started, the application is accessible at `http://localhost:8080`.

## Development Conventions

*   **Dependency Management:** Project dependencies are managed in the `pom.xml` file.
*   **Configuration:** The main configuration is in `src/main/resources/application.properties`, which sets up the H2 in-memory database.
*   **Entry Point:** The application's main entry point is `src/main/java/com/freedom/securitysamples/JavaCodeSimpleApplication.java`.
*   **Vulnerability Demos:** Each vulnerability is demonstrated in a dedicated controller within the `com.freedom.securitysamples.vulnerability` package. These controllers clearly document the vulnerability, provide example payloads, and show the insecure code. The corresponding `sec` package shows the fix.
*   **API Documentation:** The project uses `springdoc-openapi` to generate a Swagger UI for API documentation, which is available at `http://localhost:8080/swagger-ui/index.html` when the application is running.
