package no.uutilsynet.testlab2securitylib

import org.springframework.core.convert.converter.Converter
import org.springframework.security.authentication.AbstractAuthenticationToken
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.oauth2.jwt.Jwt
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken

class Testlab2AuthenticationConverter : Converter<Jwt, AbstractAuthenticationToken> {
  override fun convert(jwt: Jwt): AbstractAuthenticationToken {
    var realm_access = jwt.getClaim<Map<String, List<String>>>("realm_access")
    var roles: List<String> = realm_access.getOrDefault("roles", emptyList())
    var authorities = roles.map(::SimpleGrantedAuthority).toHashSet()

    return JwtAuthenticationToken(jwt, authorities)
  }
}
