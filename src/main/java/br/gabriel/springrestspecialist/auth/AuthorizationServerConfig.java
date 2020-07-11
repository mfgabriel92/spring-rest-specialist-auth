package br.gabriel.springrestspecialist.auth;

import java.security.KeyPair;
import java.util.Arrays;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.CompositeTokenGranter;
import org.springframework.security.oauth2.provider.TokenGranter;
import org.springframework.security.oauth2.provider.approval.ApprovalStore;
import org.springframework.security.oauth2.provider.approval.TokenApprovalStore;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.KeyStoreKeyFactory;

@SuppressWarnings("deprecation")
@Configuration
@EnableAuthorizationServer
public class AuthorizationServerConfig extends AuthorizationServerConfigurerAdapter {
    @Autowired
    private PasswordEncoder encoder;

    @Autowired
    private AuthenticationManager manager;

    @Qualifier("userDetailsService")
    @Autowired
    private UserDetailsService userDetails;

    @Autowired
    private JwtKeystoreProperties properties;
    
    @Override
    public void configure(AuthorizationServerSecurityConfigurer security) throws Exception {
        security.checkTokenAccess("isAuthenticated()");
    }
    
    @Override
    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
        clients
            .inMemory()
                .withClient("spring-rest-specialist-web")
                    .secret(encoder.encode("web"))
                    .authorizedGrantTypes("password", "refresh_token")
                    .scopes("write", "read")
                    .accessTokenValiditySeconds(60 * 60)
                    .refreshTokenValiditySeconds(60 * 60 * 24 * 7)
            .and()
                .withClient("spring-rest-specialist-client-credentials")
                    .secret(encoder.encode("client-credentials"))
                    .authorizedGrantTypes("client_credentials")
                    .scopes("read")
            .and()
                .withClient("spring-rest-specialist-authorization-code")
                    .secret(encoder.encode("authorization-code"))
                    .authorizedGrantTypes("authorization_code")
                    .scopes("write", "read")
                    .redirectUris("http://another-application")
            .and()
                .withClient("spring-rest-specialist-implicit")
                    .authorizedGrantTypes("implicit")
                    .scopes("write", "read")
                    .redirectUris("http://another-application")
            .and()
                .withClient("resourceserver")
                    .secret(encoder.encode("resourceserver999"));
    }

    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints) {
        endpoints
            .authenticationManager(manager)
            .userDetailsService(userDetails)
            .tokenGranter(tokenGranter(endpoints))
            .accessTokenConverter(jwtAccessTokenConverter())
            .approvalStore(approvalStore(endpoints.getTokenStore()));
    }

    private TokenGranter tokenGranter(AuthorizationServerEndpointsConfigurer endpoints) {
        PkceAuthorizationCodeTokenGranter pkceAuthorizationCodeTokenGranter = new PkceAuthorizationCodeTokenGranter(
            endpoints.getTokenServices(),
            endpoints.getAuthorizationCodeServices(), endpoints.getClientDetailsService(),
            endpoints.getOAuth2RequestFactory()
        );

        List<TokenGranter> granters = Arrays.asList(pkceAuthorizationCodeTokenGranter, endpoints.getTokenGranter());

        return new CompositeTokenGranter(granters);
    }
    
    @Bean
    protected JwtAccessTokenConverter jwtAccessTokenConverter() {
        String path = properties.getPath();
        String password = properties.getKeystorePassword();
        String alias = properties.getAlias();

        JwtAccessTokenConverter converter = new JwtAccessTokenConverter();
        ClassPathResource jksFile = new ClassPathResource(path);
        KeyStoreKeyFactory keyFactory = new KeyStoreKeyFactory(jksFile, password.toCharArray());
        KeyPair keyPair = keyFactory.getKeyPair(alias);

        converter.setKeyPair(keyPair);
        
        return converter;
    }

    private ApprovalStore approvalStore(TokenStore tokenStore) {
        TokenApprovalStore approvalStore = new TokenApprovalStore();
        approvalStore.setTokenStore(tokenStore);

        return approvalStore;
    }
}
