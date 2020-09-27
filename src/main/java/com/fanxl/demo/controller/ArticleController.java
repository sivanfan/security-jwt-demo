package com.fanxl.demo.controller;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("article")
public class ArticleController {
	Logger logger= LoggerFactory.getLogger(ArticleController.class);
	@GetMapping("get/{id}")
	public String load(@PathVariable Long id) {
		return "This is my first blog";
	}
	
	@PostMapping("add")
	public void create(@AuthenticationPrincipal UserDetails user) {
		
	}
	@PostMapping("test")
	public String test() {
		logger.info("This is test");
		return "This is test";
	}

}
