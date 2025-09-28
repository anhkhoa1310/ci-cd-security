package com.example.bankapp;

public class BadCodeExample {

    public void bugDemo() {
        // NullPointer bug
        String name = null;
        System.out.println(name.length());
    }

    public void vulnerabilityDemo() {
        // Hardcoded password
        String password = "123456";

        // SQL Injection nguy cơ (nếu xài JDBC)
        String userInput = "' OR 1=1 --";
        String query = "SELECT * FROM users WHERE username = '" + userInput + "'";
        System.out.println(query);
    }

    public void codeSmellDemo() {
        // Biến không dùng
        int unusedVariable = 42;

        // Cấu trúc rối
        for (int i = 0; i < 1; i++) {
            for (int j = 0; j < 1; j++) {
                for (int k = 0; k < 1; k++) {
                    System.out.println("Nested too deep");
                }
            }
        }
    }
}
