package com.example.demo.controller;

import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * @author zbw
 **/
@RestController("/admin")
public class AdminTestController {

    @RequestMapping("/home")
    public String productInfo() {
        return " admin home page ";
    }
}
