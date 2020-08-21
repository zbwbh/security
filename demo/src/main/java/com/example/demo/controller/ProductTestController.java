package com.example.demo.controller;

import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * @author zbw
 **/
@RestController("/product")
public class ProductTestController {

    @RequestMapping("/info")
    public String productInfo() {
        return " some product info ";
    }

}
