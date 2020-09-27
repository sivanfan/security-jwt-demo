package com.fanxl.demo.security.jwt.configuration;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.http.HttpStatus;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;

/***
 * 数据接口请求 jwt校验 校验失败的时候，返回给客户端的response的定制化
 * @author fanxl
 * @date 2020/9/27 10:02
 */
public class HttpStatusLoginFailureHandler implements AuthenticationFailureHandler{

	@Override
	public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
			AuthenticationException exception) throws IOException, ServletException {
		response.setStatus(HttpStatus.UNAUTHORIZED.value());
		response.setCharacterEncoding("UTF-8");
		response.setContentType("application/json");
		response.getWriter().println("{\"result\":\"Authenticate fail.\",\"msg\":\"" + exception.getLocalizedMessage() + "\"}");
	}
	
}
