package com.fanxl.demo.security.jwt.service;

import java.util.Date;

import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCrypt;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;

public class JwtUserService implements UserDetailsService{
	
	private PasswordEncoder passwordEncoder;
	
	public JwtUserService() {
		this.passwordEncoder = PasswordEncoderFactories.createDelegatingPasswordEncoder();  //默认使用 bcrypt， strength=10 
	}
	//验证用户请求中携带的token的合法性时使用，根据传入的用户名，取出saveUserLoginInfo()中缓存的 salt盐值，还要查询出用户最新的
	//角色，返回给JwtAuthenticationProvider类中的authenticate方法进行jwt校验，然后在把JwtAuthenticationToken对象往下传递，进行url权限的校验。
	//loadUserByUsername最好做下cache，这样就不用每次都去查询数据库了
	public UserDetails getUserLoginInfo(String username) {
		String salt = "123456ef";
			/**
		 * @todo 从数据库或者缓存中取出jwt token生成时用的salt
		 * salt = redisTemplate.opsForValue().get("token:"+username);
		 */
		UserDetails user = loadUserByUsername(username);
		//将salt放到password字段返回
		return User.builder().username(user.getUsername()).password(salt).authorities(user.getAuthorities()).build();
	}
	//1.登录成功以后，把生成的token值返回给用户
	//2.把此次用户登录生成的盐保存到redis或数据库中，该盐值后面jwtToken校验的时候会用到
	public String saveUserLoginInfo(UserDetails user) {
		String salt = "123456ef"; //BCrypt.gensalt();  正式开发时可以调用该方法实时生成加密的salt
		/**
    	 * @todo 将salt保存到数据库或者缓存中
    	 * redisTemplate.opsForValue().set("token:"+username, salt, 3600, TimeUnit.SECONDS);
    	 */   	
		Algorithm algorithm = Algorithm.HMAC256(salt);
		Date date = new Date(System.currentTimeMillis()+600*1000);  //设置1小时后过期
        return JWT.create()
        		.withSubject(user.getUsername())
                .withExpiresAt(date)
                .withIssuedAt(new Date())
                .sign(algorithm);
	}
	//根据用户输入的用户名，到数据库中查出该用户的详细信息，包括密码和该用户所拥有的角色，
	//返回的UserDetails对象和登录时输入的用户名密码生成的MyUsernamePasswordAuthenticationFilter中返回的Authentication中的UserDetails
	//对象做对比。
	//loadUserByUsername最好做下cache，这样就不用每次都去查询数据库了
	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		return User.builder()
				.username("Jack")
				.password(passwordEncoder.encode("jack-password"))
				.roles("USER","ADMIN")
				.build();
	}
	
	public void createUser(String username, String password) {
		String encryptPwd = passwordEncoder.encode(password);
		/**
		 * @todo 保存用户名和加密后密码到数据库
		 */
	}
	//从redis或者数据库中把 username 对应的 盐值 删除，这样后面做getUserLoginInfo的时候取不到salt直接抛出异常
	public void deleteUserLoginInfo(String username) {
		/**
		 * @todo 清除数据库或者缓存中登录salt
		 */
	}
}
