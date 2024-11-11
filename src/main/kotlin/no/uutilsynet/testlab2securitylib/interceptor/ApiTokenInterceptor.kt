package no.uutilsynet.testlab2securitylib.interceptor

import no.uutilsynet.testlab2securitylib.ApiKeyAuthenticationProperties
import org.springframework.context.annotation.Profile
import org.springframework.http.HttpRequest
import org.springframework.http.client.ClientHttpRequestExecution
import org.springframework.http.client.ClientHttpRequestInterceptor
import org.springframework.http.client.ClientHttpResponse
import org.springframework.stereotype.Component

@Component
@Profile("tokenClient")
class ApiTokenInterceptor(val apiKeyAuthenticationProperties: ApiKeyAuthenticationProperties) :
    ClientHttpRequestInterceptor {
  override fun intercept(
      request: HttpRequest,
      body: ByteArray,
      execution: ClientHttpRequestExecution
  ): ClientHttpResponse {
    request.headers[apiKeyAuthenticationProperties.headerName] =
        apiKeyAuthenticationProperties.token
    return execution.execute(request, body)
  }
}
