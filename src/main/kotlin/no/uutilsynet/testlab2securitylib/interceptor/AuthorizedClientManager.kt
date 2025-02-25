package no.uutilsynet.testlab2securitylib.interceptor

import org.springframework.context.annotation.Profile
import org.springframework.security.oauth2.client.OAuth2AuthorizeRequest
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientProviderBuilder
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizedClientManager
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository
import org.springframework.stereotype.Component

@Component("OAuth2AuthorizedClientManager")
@Profile("oidcclient")
class AuthorizedClientManager(
    clientRegistrationRepository: ClientRegistrationRepository,
    authorizedClientRepository: OAuth2AuthorizedClientRepository
) : OAuth2AuthorizedClientManager {

  private var authorizedClientManager: DefaultOAuth2AuthorizedClientManager =
      DefaultOAuth2AuthorizedClientManager(clientRegistrationRepository, authorizedClientRepository)

  init {
    val authorizedClientProvider =
        OAuth2AuthorizedClientProviderBuilder.builder().authorizationCode().refreshToken().build()
    authorizedClientManager.setAuthorizedClientProvider(authorizedClientProvider)
  }

  override fun authorize(authorizeRequest: OAuth2AuthorizeRequest?): OAuth2AuthorizedClient? {
    return authorizedClientManager.authorize(authorizeRequest)
  }
}
