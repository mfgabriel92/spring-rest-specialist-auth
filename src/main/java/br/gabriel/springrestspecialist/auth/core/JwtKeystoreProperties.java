package br.gabriel.springrestspecialist.auth.core;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;
import org.springframework.validation.annotation.Validated;

@Validated
@Component
@ConfigurationProperties("srs.jwt.keystore")
@Getter
@Setter
public class JwtKeystoreProperties {
    private String path;

    private String keystorePassword;

    private String alias;
}
