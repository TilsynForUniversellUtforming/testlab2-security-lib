package no.uutilsynet.testlab2securitylib.apitoken

import no.uutilsynet.testlab2securitylib.ApiKeyAuthenticationProperties
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Test
import org.springframework.mock.web.MockFilterChain
import org.springframework.mock.web.MockHttpServletRequest
import org.springframework.mock.web.MockHttpServletResponse
import org.springframework.security.core.context.SecurityContextHolder

class AuthenticationFilterTest {

  private val token = "valid-token"
  private val headerName = "X-API-KEY"
  private val tokenAuthenticationService =
      TokenAuthenticationService(TestApiKeyAuthenticationProperties(headerName, token))
  private val filter = AuthenticationFilter(tokenAuthenticationService)

  @AfterEach
  fun tearDown() {
    SecurityContextHolder.clearContext()
  }

  @Test
  fun `sets authentication and continues chain when configured header is valid`() {
    val request = MockHttpServletRequest("GET", "/api/test")
    request.addHeader(headerName, token)
    val response = MockHttpServletResponse()
    val chain = MockFilterChain()

    filter.doFilter(request, response, chain)

    assertNotNull(chain.request)
    assertEquals(token, SecurityContextHolder.getContext()?.authentication?.principal)
  }

  @Test
  fun `returns unauthorized and stops chain when configured header has invalid token`() {
    val request = MockHttpServletRequest("GET", "/api/test")
    request.addHeader(headerName, "wrong-token")
    val response = MockHttpServletResponse()
    val chain = MockFilterChain()

    filter.doFilter(request, response, chain)

    assertEquals(MockHttpServletResponse.SC_UNAUTHORIZED, response.status)
    assertEquals("Invalid API Key", response.contentAsString)
    assertNull(chain.request)
  }

  @Test
  fun `skips authentication and continues chain when configured header is missing`() {
    val request = MockHttpServletRequest("GET", "/api/test")
    val response = MockHttpServletResponse()
    val chain = MockFilterChain()

    filter.doFilter(request, response, chain)

    assertNotNull(chain.request)
    assertNull(SecurityContextHolder.getContext().authentication)
  }

  private data class TestApiKeyAuthenticationProperties(
      override val headerName: String,
      override val token: String
  ) : ApiKeyAuthenticationProperties
}
