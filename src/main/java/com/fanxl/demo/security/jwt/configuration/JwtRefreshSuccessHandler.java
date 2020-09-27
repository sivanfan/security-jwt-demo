package com.fanxl.demo.security.jwt.configuration;

import java.io.IOException;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Date;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.fanxl.demo.security.jwt.service.JwtUserService;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import com.auth0.jwt.interfaces.DecodedJWT;

/***
 * JwtAuthenticationProvider中token验证成功以后，执行的动作
 * 根据设置的更新时间，判断是否需要更新token，如需要就生产新的token放在response的header中返回给用户
 * 比如 token生成是的过期时间是5分钟，那么 刷新时间可以设置成4分钟，这样就可以实行用户token的自动刷新
 * @author fanxl
 * @date 2020/9/27 12:25
*/
public class JwtRefreshSuccessHandler implements AuthenticationSuccessHandler{
	
	private static final int tokenRefreshInterval = 300;  //刷新间隔5分钟
	
	private JwtUserService jwtUserService;
	
	public JwtRefreshSuccessHandler(JwtUserService jwtUserService) {
		this.jwtUserService = jwtUserService;
	}

	@Override
	public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
			Authentication authentication) throws IOException, ServletException {
		DecodedJWT jwt = ((JwtAuthenticationToken)authentication).getToken();
		boolean shouldRefresh = shouldTokenRefresh(jwt.getIssuedAt());
		if(shouldRefresh) {
            String newToken = jwtUserService.saveUserLoginInfo((UserDetails)authentication.getPrincipal());
            response.setHeader("Authorization", newToken);
        }	
	}
	
	protected boolean shouldTokenRefresh(Date issueAt){
        LocalDateTime issueTime = LocalDateTime.ofInstant(issueAt.toInstant(), ZoneId.systemDefault());
        return LocalDateTime.now().minusSeconds(tokenRefreshInterval).isAfter(issueTime);
    }

}
