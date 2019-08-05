package com.example.pjmall.backend.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;


@Configuration
@EnableWebSecurity
public class AppSecurityConfig extends WebSecurityConfigurerAdapter{
	
	@Override
	public void configure(WebSecurity web) throws Exception {
		super.configure(web);
	}


	protected void configure(HttpSecurity http) throws Exception {
		
		// 1. ACL 설정
			http.authorizeRequests()
			
			// 인증이 되어있을 때 (Authenticated?)
			.antMatchers("/user/update", "/user/logout").authenticated()
			.antMatchers("/board/write", "/board/modify", "/board/delete").authenticated()
		
			// ADMIN Authorization ( ADMIN 권한, ROLE_ADMIN)
			.antMatchers("/admin/**").hasAuthority("ROLE_ADMIN")
			.antMatchers("/admin/upload", "/admin/delete/").hasAuthority("ROLE_ADMIN")

			// 모두 허용
			.anyRequest().permitAll();
			
	}

	/**
	 * UserDetailService를 설정
	 */
	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		super.configure(auth);
	}
	
}
