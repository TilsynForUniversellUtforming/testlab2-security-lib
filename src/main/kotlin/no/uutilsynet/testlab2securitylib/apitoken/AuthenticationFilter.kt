package no.uutilsynet.testlab2securitylib.apitoken

import jakarta.servlet.FilterChain
import jakarta.servlet.ServletException
import jakarta.servlet.ServletRequest
import jakarta.servlet.ServletResponse
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import java.io.IOException
import org.springframework.http.MediaType
import org.springframework.security.core.Authentication
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.web.filter.GenericFilterBean

class AuthenticationFilter(val tokenAuthenticationService: TokenAuthenticationService) :
    GenericFilterBean() {

  @Throws(IOException::class, ServletException::class)
  override fun doFilter(
      request: ServletRequest,
      response: ServletResponse,
      filterChain: FilterChain
  ) {
    if ((request as HttpServletRequest).getHeader("X-API-KEY") != null) {
      try {
        val authentication: Authentication = tokenAuthenticationService.getAuthentication(request)
        SecurityContextHolder.getContext().authentication = authentication
      } catch (exp: Exception) {
        val httpResponse = response as HttpServletResponse
        httpResponse.status = HttpServletResponse.SC_UNAUTHORIZED
        httpResponse.contentType = MediaType.APPLICATION_JSON_VALUE
        val writer = httpResponse.writer
        writer.print(exp.message)
        writer.flush()
        writer.close()
      }
    }

    filterChain.doFilter(request, response)
  }
}
