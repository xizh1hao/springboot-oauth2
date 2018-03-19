package com.example.server.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;


@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {

    
    @Autowired
    public void globalUserDetails(AuthenticationManagerBuilder auth) throws Exception {
         auth.inMemoryAuthentication()
         .withUser("admin").password("123456").roles("ADMIN");
        //配置用户来源于数据库
//        auth.userDetailsService(userDetailsService());
    }
    
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
        .authorizeRequests()
        .antMatchers("/","/home").permitAll()
        .anyRequest().authenticated()
        .and().httpBasic()
        .and().csrf().disable();
    }

    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }
    
//    @Bean
//    public UserDetailsService userDetailsService() {
//        return new UserDetailsService() {
//            @Override
//            public UserDetails loadUserByUsername(String name) throws UsernameNotFoundException {
//                // 通过用户名获取用户信息
//                Account account = accountRepository.findByName(name);
//                if (account != null) {
//                    // 创建spring security安全用户
//                    User user = new User(account.getName(), account.getPassword(),
//                            AuthorityUtils.createAuthorityList(account.getRoles()));
//                    return user;
//                } else {
//                    throw new UsernameNotFoundException("用户[" + name + "]不存在");
//                }
//            }
//        };
//
//    }
    
}
