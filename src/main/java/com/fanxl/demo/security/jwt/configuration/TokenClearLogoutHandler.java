package com.fanxl.demo.security.jwt.configuration;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.fanxl.demo.security.jwt.service.JwtUserService;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.logout.LogoutHandler;

/***
 * 调用logout方法执行的动作，把该用户登录时生产的salt删除，这样后面再来请求的是token校验就是失败的，实现了退出功能
 * @author fanxl
 * @date 2020/9/27 12:24
*/
public class TokenClearLogoutHandler implements LogoutHandler {
	
	private JwtUserService jwtUserService;
	
	public TokenClearLogoutHandler(JwtUserService jwtUserService) {
		this.jwtUserService = jwtUserService;
	}

	@Override
	public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
		clearToken(authentication);
	}
	
	protected void clearToken(Authentication authentication) {
		if(authentication == null)
			return;
		UserDetails user = (UserDetails)authentication.getPrincipal();
		if(user!=null && user.getUsername()!=null)
		    jwtUserService.deleteUserLoginInfo(user.getUsername());
	}

}
