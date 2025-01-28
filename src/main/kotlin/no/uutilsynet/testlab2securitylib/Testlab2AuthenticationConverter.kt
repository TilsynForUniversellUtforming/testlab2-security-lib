package no.uutilsynet.testlab2securitylib

import org.springframework.core.convert.converter.Converter
import org.springframework.security.authentication.AbstractAuthenticationToken
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.oauth2.jwt.Jwt
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken

class Testlab2AuthenticationConverter : Converter<Jwt, AbstractAuthenticationToken> {
  override fun convert(jwt: Jwt): AbstractAuthenticationToken {
    val realmAccess = jwt.getClaim<Map<String, List<String>>>("realm_access")
    val roles: List<String> = realmAccess.getOrDefault("roles", emptyList())
    val authorities = roles.map(::SimpleGrantedAuthority).toHashSet()
    val name = jwt.getClaim<String>("preferred_username")

    return JwtAuthenticationToken(jwt, authorities, name)
  }
}
