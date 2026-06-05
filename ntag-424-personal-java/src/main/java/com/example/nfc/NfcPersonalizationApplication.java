package com.example.nfc;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;

@SpringBootApplication
public class NfcPersonalizationApplication {

    public static void main(String[] args) {
        loadDotEnv();
        SpringApplication.run(NfcPersonalizationApplication.class, args);
    }

    private static void loadDotEnv() {
        // Look for .env in current directory and parent directory
        Path[] envPaths = {
            Paths.get(".env"),
            Paths.get("../.env")
        };

        boolean loaded = false;
        for (Path path : envPaths) {
            if (Files.exists(path)) {
                try {
                    List<String> lines = Files.readAllLines(path);
                    for (String line : lines) {
                        line = line.trim();
                        if (line.isEmpty() || line.startsWith("#")) {
                            continue;
                        }
                        String[] parts = line.split("=", 2);
                        if (parts.length == 2) {
                            String key = parts[0].trim();
                            String value = parts[1].trim();
                            
                            // Remove surrounding quotes if they exist
                            if (value.startsWith("\"") && value.endsWith("\"")) {
                                value = value.substring(1, value.length() - 1);
                            } else if (value.startsWith("'") && value.endsWith("'")) {
                                value = value.substring(1, value.length() - 1);
                            }
                            
                            System.setProperty(key, value);
                        }
                    }
                    System.out.println("Loaded environment configuration from: " + path.toAbsolutePath());
                    loaded = true;
                    break;
                } catch (IOException e) {
                    System.err.println("Failed to read environment file at " + path + ": " + e.getMessage());
                }
            }
        }
        
        if (!loaded) {
            System.out.println("No .env file found at standard locations. Using system environment variables.");
        }
    }
}
