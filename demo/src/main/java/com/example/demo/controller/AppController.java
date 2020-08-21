package com.example.demo.controller;

import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * @author zbw
 **/
@RestController
public class AppController {

    @RequestMapping("/hello")
    String home() {
        return "Hello, spring security!";
    }
}
