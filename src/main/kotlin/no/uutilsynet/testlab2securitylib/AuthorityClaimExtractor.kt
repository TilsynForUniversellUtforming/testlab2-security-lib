package no.uutilsynet.testlab2securitylib

import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.authority.SimpleGrantedAuthority

object AuthorityClaimExtractor {

  fun extractAuthorities(claims: Map<String, Any>): Set<GrantedAuthority> {
    val realmAccessRoles = extractRealmAccessRoles(claims)
    val userRealmRoles = extractStringCollectionClaim(claims, "user_realm_roles")

    return (realmAccessRoles + userRealmRoles).map(::SimpleGrantedAuthority).toSet()
  }

  private fun extractRealmAccessRoles(claims: Map<String, Any>): List<String> {
    val realmAccess = claims["realm_access"] as? Map<*, *> ?: return emptyList()
    return (realmAccess["roles"] as? Collection<*>)?.filterIsInstance<String>().orEmpty()
  }

  private fun extractStringCollectionClaim(
      claims: Map<String, Any>,
      claimName: String
  ): List<String> = (claims[claimName] as? Collection<*>)?.filterIsInstance<String>().orEmpty()
}
