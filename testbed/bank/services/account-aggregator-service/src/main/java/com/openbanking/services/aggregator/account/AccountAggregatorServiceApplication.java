package com.openbanking.services.aggregator.account;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.web.reactive.function.client.WebClient;

import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.ExternalDocumentation;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Contact;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.info.License;
import io.swagger.v3.oas.models.security.OAuthFlow;
import io.swagger.v3.oas.models.security.OAuthFlows;
import io.swagger.v3.oas.models.security.Scopes;
import io.swagger.v3.oas.models.security.SecurityRequirement;
import io.swagger.v3.oas.models.security.SecurityScheme;

@SpringBootApplication
@ComponentScan("com.openbanking")
public class AccountAggregatorServiceApplication {
	@Value("${api.common.version}")         String apiVersion;
	@Value("${api.common.title}")           String apiTitle;
	@Value("${api.common.description}")     String apiDescription;
	@Value("${api.common.termsOfService}")  String apiTermsOfService;
	@Value("${api.common.license}")         String apiLicense;
	@Value("${api.common.licenseUrl}")      String apiLicenseUrl;
	@Value("${api.common.externalDocDesc}") String apiExternalDocDesc;
	@Value("${api.common.externalDocUrl}")  String apiExternalDocUrl;
	@Value("${api.common.contact.name}")    String apiContactName;
	@Value("${api.common.contact.url}")     String apiContactUrl;
	@Value("${api.common.contact.email}")   String apiContactEmail;
	/**
	 * Will exposed on $HOST:$PORT/swagger-ui.html
	 *
	 * @return the common OpenAPI documentation
	 */
	@Bean
	public OpenAPI getOpenApiDocumentation() {
		return new OpenAPI()
		.info(new Info().title(apiTitle)
			.description(apiDescription)
			.version(apiVersion)
			.contact(new Contact()
			.name(apiContactName)
			.url(apiContactUrl)
			.email(apiContactEmail))
			.termsOfService(apiTermsOfService)
			.license(new License()
			.name(apiLicense)
			.url(apiLicenseUrl)))
		.externalDocs(new ExternalDocumentation()
			.description(apiExternalDocDesc)
			.url(apiExternalDocUrl))
		.addSecurityItem(new SecurityRequirement().addList("oauth2"))
		.components(new Components()
			.addSecuritySchemes("oauth2", new SecurityScheme()
				.type(SecurityScheme.Type.OAUTH2)
				.flows(new OAuthFlows()
					.clientCredentials(new OAuthFlow()
						.tokenUrl("https://localhost:8443/oauth2/token")
						.scopes(new Scopes()
							.addString("account:read", "Read account data")
							.addString("account:write", "Write account data"))))));
	}

	@Bean
	public WebClient.Builder loadBalancedWebClientBuilder() {
		return WebClient.builder();
	}

	// Client for the consent revocation cross-check with the AS (in-mesh). Fail-open, short cache TTL.
	@Bean
	public ConsentStatusClient consentStatusClient(WebClient.Builder builder,
			@org.springframework.beans.factory.annotation.Value("${app.consent.revocation-check.enabled:true}") boolean enabled,
			@org.springframework.beans.factory.annotation.Value("${app.consent.status-base-url:http://auth-server}") String baseUrl,
			@org.springframework.beans.factory.annotation.Value("${app.consent.status-cache-ttl-seconds:15}") long ttlSeconds) {
		return new ConsentStatusClient(builder, baseUrl, enabled, ttlSeconds);
	}

	public static void main(String[] args) {
		SpringApplication.run(AccountAggregatorServiceApplication.class, args);
	}

}
