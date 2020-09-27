package com.fanxl.demo.security.jwt.configuration;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.fanxl.demo.security.jwt.service.JwtUserService;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

/***
 * 登录成功以后，执行的动作。调用saveUserLoginInfo方法，
 * 1、把该 username的salt保存
 * 2、生成 token返回给 客户端
 * @author fanxl
 * @date 2020/9/27 12:29
 */
public class JsonLoginSuccessHandler implements AuthenticationSuccessHandler{
	
	private JwtUserService jwtUserService;
	
	public JsonLoginSuccessHandler(JwtUserService jwtUserService) {
		this.jwtUserService = jwtUserService;
	}

	@Override
	public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
			Authentication authentication) throws IOException, ServletException {
		String token = jwtUserService.saveUserLoginInfo((UserDetails)authentication.getPrincipal());
		response.setHeader("Authorization", token);
	}
	
}
