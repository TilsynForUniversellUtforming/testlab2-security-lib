package no.uutilsynet.testlab2securitylib

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.oauth2.core.oidc.OidcIdToken
import org.springframework.security.oauth2.core.oidc.OidcUserInfo
import org.springframework.security.oauth2.core.oidc.user.OidcUserAuthority
import org.springframework.security.oauth2.jwt.Jwt

class SecurityLibConfigTest {

  @Test
  fun `oauth2 mapper extracts authorities from realm_access and user_realm_roles`() {
    val idToken =
        OidcIdToken.withTokenValue("Testtoken")
            .claim("realm_access", mapOf("roles" to listOf("brukar subscriber")))
            .build()

    val userInfo: OidcUserInfo =
        OidcUserInfo.builder().claim("user_realm_roles", listOf("brukar editor")).build()

    val userAuthority: OidcUserAuthority = OidcUserAuthority(idToken, userInfo)
    val mapper = Testlab2OAuth2UserAuthoritiesMapper()

    val authorities = mapper.mapAuthorities(setOf(userAuthority))

    assertTrue(authorities.contains(userAuthority))
    assertTrue(authorities.contains(SimpleGrantedAuthority("brukar subscriber")))
    assertTrue(authorities.contains(SimpleGrantedAuthority("brukar editor")))
  }

  @Test
  fun `jwt converter extracts authorities in the same way as oauth2 login mapper`() {
    val jwt =
        Jwt.withTokenValue("token")
            .header("alg", "none")
            .claim("preferred_username", "alice")
            .claim("realm_access", mapOf("roles" to listOf("brukar subscriber")))
            .claim("user_realm_roles", listOf("brukar editor"))
            .build()

    val converter = Testlab2AuthenticationConverter()
    val authentication = converter.convert(jwt)
    val authorities = authentication.authorities.map { it.authority }.toSet()

    assertEquals("alice", authentication.name)
    assertEquals(setOf("brukar subscriber", "brukar editor"), authorities)
  }
}
