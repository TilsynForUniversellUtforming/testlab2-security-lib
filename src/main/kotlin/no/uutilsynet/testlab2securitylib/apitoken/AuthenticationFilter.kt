package no.uutilsynet.testlab2securitylib.apitoken

import jakarta.servlet.FilterChain
import jakarta.servlet.ServletException
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import java.io.IOException
import org.springframework.http.MediaType
import org.springframework.security.core.Authentication
import org.springframework.security.core.AuthenticationException
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter
import org.springframework.security.web.util.matcher.RequestHeaderRequestMatcher

class AuthenticationFilter(val tokenAuthenticationService: TokenAuthenticationService) :
    AbstractAuthenticationProcessingFilter(
        RequestHeaderRequestMatcher(tokenAuthenticationService.properties.headerName)) {

  override fun attemptAuthentication(
      request: HttpServletRequest,
      response: HttpServletResponse
  ): Authentication {
    return tokenAuthenticationService.getAuthentication(request)
  }

  @Throws(IOException::class, ServletException::class)
  override fun successfulAuthentication(
      request: HttpServletRequest,
      response: HttpServletResponse,
      chain: FilterChain,
      authResult: Authentication
  ) {
    SecurityContextHolder.getContext().authentication = authResult
    chain.doFilter(request, response)
  }

  override fun unsuccessfulAuthentication(
      request: HttpServletRequest,
      response: HttpServletResponse,
      failed: AuthenticationException
  ) {
    response.status = HttpServletResponse.SC_UNAUTHORIZED
    response.contentType = MediaType.APPLICATION_JSON_VALUE
    response.writer.use { writer -> writer.print(failed.message) }
  }
}
