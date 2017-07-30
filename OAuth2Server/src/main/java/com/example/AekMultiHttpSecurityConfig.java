package com.example;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;

@EnableWebSecurity
public class AekMultiHttpSecurityConfig {
	
	@Autowired
	public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
		auth
		.inMemoryAuthentication()
		.withUser("user").password("russellchang").roles("USER")
		.and()
		.withUser("admin").password("admin").roles("USER","ADMIN");
		
	}
	@Configuration
    @Order(1)                                                        
    public static class WolfCaveWebSecurityConfigurationAdapter extends WebSecurityConfigurerAdapter {
		
	    @Override
	    @Bean
	    public AuthenticationManager authenticationManagerBean() throws Exception {
	        return super.authenticationManagerBean();
	    }
	    
            protected void configure(HttpSecurity http) throws Exception {
                    http
                            .antMatcher("/wolfcave/**")
                            .authorizeRequests()
                                    .anyRequest().hasRole("ADMIN")                                   
                                    .and()
                            .antMatcher("/oauth/authorize/**")
                            .authorizeRequests()
		                            .anyRequest().hasRole("USER")
		                            .and()
                            .httpBasic();
            }
    }
	
	@Configuration                                                   
    public static class FormLoginWebSecurityConfigurerAdapter extends WebSecurityConfigurerAdapter {

            @Override
            protected void configure(HttpSecurity http) throws Exception {
                    http
                            .authorizeRequests()
                                    .anyRequest().authenticated()
                                    .and()
                            .formLogin();
            }
    }

}
