package no.uutilsynet.testlab2securitylib

import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.context.annotation.Profile
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.invoke
import org.springframework.security.web.SecurityFilterChain

@Configuration("securitylibConfig")
open class SecurityLibConfig {

  @Bean("securitylibFilterChain")
  @Profile("!security")
  open fun securitylibFilterChain(http: HttpSecurity): SecurityFilterChain {
    http {
      authorizeHttpRequests { authorize(anyRequest, permitAll) }
      cors {}
      csrf { disable() }
    }
    return http.build()
  }
}
