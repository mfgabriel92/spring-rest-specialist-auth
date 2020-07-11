package br.gabriel.springrestspecialist.auth.core;

import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.TokenEnhancer;

import java.util.HashMap;

public class JwtTokenEnhancer implements TokenEnhancer {
    @Override
    public OAuth2AccessToken enhance(OAuth2AccessToken accessToken, OAuth2Authentication authentication) {
        if (authentication.getPrincipal() instanceof AuthUser) {
            AuthUser user = (AuthUser) authentication.getPrincipal();
            DefaultOAuth2AccessToken token = (DefaultOAuth2AccessToken) accessToken;

            HashMap<String, Object> info = new HashMap<>();
            info.put("user_id", user.getId());
            info.put("name", user.getName());

            token.setAdditionalInformation(info);
        }

        return accessToken;
    }
}
