package com.freedom.securitysamples.config;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;

/**
 * Global exception handler for the application.
 * This class uses Spring's @ControllerAdvice to provide centralized
 * exception handling across all @Controller classes.
 */
@ControllerAdvice
public class GlobalExceptionHandler {

    /**
     * Handles generic unexpected exceptions.
     *
     * @param ex The unexpected exception.
     * @return A ResponseEntity with a 500 Internal Server Error status and a custom error message.
     */
    @ExceptionHandler(Exception.class)
    public ResponseEntity<Map<String, Object>> handleAllUncaughtException(Exception ex) {
        Map<String, Object> errorDetails = new HashMap<>();
        errorDetails.put("timestamp", LocalDateTime.now());
        errorDetails.put("status", HttpStatus.INTERNAL_SERVER_ERROR.value());
        errorDetails.put("error", "Internal Server Error");
        errorDetails.put("message", "An unexpected error occurred. Please try again later.");
        errorDetails.put("details", ex.getMessage()); // For debugging, consider removing in production
        return new ResponseEntity<>(errorDetails, HttpStatus.INTERNAL_SERVER_ERROR);
    }

    // You can add more specific exception handlers here, for example:
    // @ExceptionHandler(IllegalArgumentException.class)
    // public ResponseEntity<Map<String, Object>> handleIllegalArgumentException(IllegalArgumentException ex) {
    //     Map<String, Object> errorDetails = new HashMap<>();
    //     errorDetails.put("timestamp", LocalDateTime.now());
    //     errorDetails.put("status", HttpStatus.BAD_REQUEST.value());
    //     errorDetails.put("error", "Bad Request");
    //     errorDetails.put("message", ex.getMessage());
    //     return new ResponseEntity<>(errorDetails, HttpStatus.BAD_REQUEST);
    // }
}
