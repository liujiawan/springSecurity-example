package com.sse.oauth2.server.config;

import com.sse.oauth2.server.service.CustomUserDetailsService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.client.JdbcClientDetailsService;
import org.springframework.security.oauth2.provider.code.AuthorizationCodeServices;
import org.springframework.security.oauth2.provider.code.JdbcAuthorizationCodeServices;
import org.springframework.security.oauth2.provider.token.TokenEnhancerChain;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;

import javax.sql.DataSource;
import java.util.Arrays;

/**
 *  认证服务器配置
 * @author: GL
 * @program: springSecurity-example
 * @create: 2020年 06月 05日 10:52
 **/
@Configuration
// 开启 OAuth2 认证服务器功能
@EnableAuthorizationServer
public class AuthorizationServerConfig extends AuthorizationServerConfigurerAdapter {

    /**
     * 密码加密实例
     */
    @Autowired
    private PasswordEncoder passwordEncoder;

    /**
     * 引入AuthenticationManager实例
     */
    @Autowired
    private AuthenticationManager authenticationManager;

    /**
     * 刷新令牌
     */
    @Autowired
    private CustomUserDetailsService customUserDetailsService ;
    @Autowired
    private CustomTokenEnhancer customTokenEnhancer;

    /**
     * token管理方式，在TokenConfig类中已对添加到容器中了
     */
    @Autowired
    private TokenStore tokenStore;

    /**
     * 获取数据源
     */
    @Autowired
    private DataSource dataSource;

    /**
     * jwt转换器
     */
    @Autowired
    private JwtAccessTokenConverter jwtAccessTokenConverter;

    /**
     *  创建jdbcClientDetailsService实例，并注入spring容器中，不要少了@Bean
     *  注意：访问修饰符不要写错了。
     * @return
     */
    @Bean
    public ClientDetailsService jdbcClientDetailsService(){
        return new JdbcClientDetailsService(dataSource);
    }

    /**
     * 令牌端点的安全配置
     * @param security
     * @throws Exception
     */
    @Override
    public void configure(AuthorizationServerSecurityConfigurer security) throws Exception {
        // 所有人可访问 /oauth/token_key 后面要获取公钥, 默认拒绝访问
        security.tokenKeyAccess("permitAll()");
        // 认证后可访问 /oauth/check_token , 默认拒绝访问
        security.checkTokenAccess("isAuthenticated()");
        security.allowFormAuthenticationForClients();
    }

    /**
     * 配置被允许访问此认证服务器的客户端详情信息
     * 方式1：内存方式管理
     * 方式2：数据库管理
     */
    @Override
    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
        // 使用JDBC方式管理客服端
        clients.withClientDetails(jdbcClientDetailsService());

    }

    /**
     * 授权码管理策略
     * @return
     */
    @Bean
    public AuthorizationCodeServices jdbcAuthorizationCodeServices() {
        // 注入数据源
        return new JdbcAuthorizationCodeServices(dataSource);
    }
    /**
     * 关于认证服务器端点配置
     * @param endpoints
     * @throws Exception
     */
    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
        // 密码模式需要设置认证管理器
        endpoints.authenticationManager(authenticationManager);
        // 认证加强
        TokenEnhancerChain tokenEnhancerChain = new TokenEnhancerChain();
        tokenEnhancerChain.setTokenEnhancers(
                Arrays.asList(customTokenEnhancer, jwtAccessTokenConverter));
        endpoints.userDetailsService(customUserDetailsService);
//        endpoints.tokenEnhancer(customTokenEnhancer);
        // 令牌的管理方式，并指定JWT转换器 accessTokenConverter
        endpoints.tokenStore(tokenStore).tokenEnhancer(tokenEnhancerChain);
        // 授权码管理策略
        endpoints.authorizationCodeServices(jdbcAuthorizationCodeServices());
    }
}
