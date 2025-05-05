package no.uutilsynet.testlab2securitylib

import org.springframework.core.convert.converter.Converter
import org.springframework.security.authentication.AbstractAuthenticationToken
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.oauth2.jwt.Jwt
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken

class Testlab2AuthenticationConverter : Converter<Jwt, AbstractAuthenticationToken> {
  override fun convert(jwt: Jwt): AbstractAuthenticationToken {
    val realmAccess = getRealmAccess(jwt)
    val roles: List<String> = getRoles(realmAccess)
    val authorities = rolesToSimpleGrantedAuthorities(roles)
    val name = getUserName(jwt)

    return JwtAuthenticationToken(jwt, authorities, name)
  }

  private fun getUserName(jwt: Jwt): String? =
    jwt.getClaim<String>("preferred_username")

  private fun rolesToSimpleGrantedAuthorities(roles: List<String>):HashSet<SimpleGrantedAuthority> =
    roles.map(::SimpleGrantedAuthority).toHashSet()

  private fun getRealmAccess(jwt: Jwt): Map<String, List<String>>? =
    jwt.getClaim<Map<String, List<String>>>("realm_access")

  private fun getRoles(realmAccess: Map<String, List<String>>?): List<String> {
    if (realmAccess == null) {
      return emptyList()
    }
    return getRolesFromRealAccess(realmAccess)
  }

  private fun getRolesFromRealAccess(realmAccess: Map<String, List<String>>) =
    realmAccess.getOrDefault("roles", emptyList())
}
