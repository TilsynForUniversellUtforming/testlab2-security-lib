package no.uutilsynet.testlab2securitylib

import jakarta.servlet.http.HttpServletRequest
import org.springframework.stereotype.Component
import org.springframework.web.cors.CorsConfiguration
import org.springframework.web.cors.UrlBasedCorsConfigurationSource

@Component
class Testlab2CorsConfiguration : UrlBasedCorsConfigurationSource() {

  init {
    registerCorsConfiguration("/**", getCorsConfiguration())
  }
  override fun getCorsConfiguration(request: HttpServletRequest): CorsConfiguration {
    return getCorsConfiguration()
  }

  private fun getCorsConfiguration(): CorsConfiguration {
    val configuration = CorsConfiguration()
    configuration.allowedOriginPatterns =
        listOf(
            "https://*.difi.no",
            "https://*.uutilsynet.no",
            "http://localhost:5173",
            "http://localhost:80")
    configuration.allowCredentials = true
    configuration.allowedMethods =
        listOf("GET", "POST", "PUT", "DELETE", "OPTIONS", "HEAD", "PATCH")
    configuration.allowedHeaders = listOf("*")
    return configuration
  }
}
