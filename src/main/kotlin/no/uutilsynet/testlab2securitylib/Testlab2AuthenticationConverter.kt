package no.uutilsynet.testlab2securitylib

import org.springframework.core.convert.converter.Converter
import org.springframework.security.authentication.AbstractAuthenticationToken
import org.springframework.security.oauth2.jwt.Jwt
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken

class Testlab2AuthenticationConverter : Converter<Jwt, AbstractAuthenticationToken> {
  override fun convert(jwt: Jwt): AbstractAuthenticationToken {
    val authorities = AuthorityClaimExtractor.extractAuthorities(jwt.claims)
    val name = getUserName(jwt)
    requireNotNull(name) { "User name is null" }

    return JwtAuthenticationToken(jwt, authorities, name)
  }

  private fun getUserName(jwt: Jwt): String? = jwt.getClaim<String>("preferred_username")
}
