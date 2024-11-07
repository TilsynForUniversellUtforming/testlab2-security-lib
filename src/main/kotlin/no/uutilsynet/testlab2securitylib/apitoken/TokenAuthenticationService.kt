package no.uutilsynet.testlab2securitylib.apitoken

import jakarta.servlet.http.HttpServletRequest
import no.uutilsynet.testlab2securitylib.ApiKeyAuthenticationProperties
import org.springframework.security.authentication.BadCredentialsException
import org.springframework.security.core.Authentication
import org.springframework.security.core.authority.AuthorityUtils

class TokenAuthenticationService(val properties: ApiKeyAuthenticationProperties) {

  fun getAuthentication(request: HttpServletRequest): Authentication {
    val apiKey = request.getHeader(properties.headerName)
    if (apiKey == null || apiKey != properties.token) {
      throw BadCredentialsException("Invalid API Key")
    }

    return ApiKeyAuthentication(apiKey, AuthorityUtils.createAuthorityList("brukar subscriber"))
  }
}
