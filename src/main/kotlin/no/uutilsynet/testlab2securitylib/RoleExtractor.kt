package no.uutilsynet.testlab2securitylib

import java.util.stream.Collectors
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.oauth2.core.oidc.user.OidcUserAuthority

class RoleExtractor {

  fun extractRoleFromClaims(oidcUserAuthority: OidcUserAuthority): Set<GrantedAuthority> {
    val claims = oidcUserAuthority.idToken.claims + oidcUserAuthority.userInfo?.claims.orEmpty()
    return AuthorityClaimExtractor.extractAuthorities(claims).stream().collect(Collectors.toSet())
  }
}
