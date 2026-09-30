package no.uutilsynet.testlab2securitylib

import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper
import org.springframework.security.oauth2.core.oidc.user.OidcUserAuthority
import org.springframework.security.oauth2.core.user.OAuth2UserAuthority

class Testlab2OAuth2UserAuthoritiesMapper : GrantedAuthoritiesMapper {

  override fun mapAuthorities(
      authorities: Collection<org.springframework.security.core.GrantedAuthority>
  ) =
      authorities.flatMapTo(linkedSetOf()) { authority ->
        when (authority) {
          is OidcUserAuthority ->
              setOf(authority) +
                  AuthorityClaimExtractor.extractAuthorities(
                      authority.idToken.claims + authority.userInfo?.claims.orEmpty())
          is OAuth2UserAuthority ->
              setOf(authority) + AuthorityClaimExtractor.extractAuthorities(authority.attributes)
          else -> setOf(authority)
        }
      }
}
