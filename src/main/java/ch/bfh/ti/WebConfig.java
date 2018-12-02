package ch.bfh.ti;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import java.util.Base64;

@Configuration
public class WebConfig implements WebMvcConfigurer {

    @Override
    public void addCorsMappings(final CorsRegistry registry) {
        registry.addMapping("/**").allowedMethods("GET", "POST", "PUT");
    }

    @Bean
    public Base64.Encoder getBase64UrlEncoder() {
        return Base64.getUrlEncoder().withoutPadding();
    }
    @Bean
    public Base64.Decoder getBase64UrlDecoder() {
        return Base64.getUrlDecoder();
    }
}
