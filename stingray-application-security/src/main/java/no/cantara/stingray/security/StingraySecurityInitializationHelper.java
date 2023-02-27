package no.cantara.stingray.security;

import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.core.Request;
import no.cantara.config.ApplicationProperties;
import no.cantara.config.ProviderLoader;
import no.cantara.stingray.application.StingrayApplication;
import no.cantara.stingray.security.application.StingraySecurityFilter;
import no.cantara.stingray.security.authentication.StingrayAuthenticationManager;
import no.cantara.stingray.security.authentication.StingrayAuthenticationManagerFactory;
import no.cantara.stingray.security.authorization.StingrayAccessManager;
import no.cantara.stingray.security.authorization.StingrayAccessManagerFactory;
import org.glassfish.jersey.server.ContainerRequest;
import org.glassfish.jersey.server.internal.routing.RoutingContext;

import java.lang.reflect.Method;
import java.util.function.BiConsumer;

class StingraySecurityInitializationHelper {

    private final StingrayApplication application;
    private final BiConsumer<StingrayApplication, ApplicationProperties.Builder> configBuilder;

    StingraySecurityInitializationHelper(StingrayApplication application, BiConsumer<StingrayApplication, ApplicationProperties.Builder> configBuilder) {
        this.application = application;
        this.configBuilder = configBuilder;
    }

    void initSecurity() {
        application.init(StingrayAuthenticationManager.class, this::createAuthenticationManager);
        application.init(StingrayAccessManager.class, this::createAccessManager);
        application.initAndRegisterJaxRsWsComponent(StingraySecurityFilter.class, this::createSecurityFilter);
    }

    StingrayAuthenticationManager createAuthenticationManager() {
        ApplicationProperties config = application.config();
        String provider = config.get("authentication.provider", "default");
        StingrayAuthenticationManager authenticationManager = ProviderLoader.configure(config, provider, StingrayAuthenticationManagerFactory.class);
        return authenticationManager;
    }

    StingrayAccessManager createAccessManager() {
        ApplicationProperties.Builder builder = ApplicationProperties.builder();
        configBuilder.accept(application, builder);
        ApplicationProperties authConfig = builder
                .build();
        String provider = application.config().get("authorization.provider", "default");
        StingrayAccessManager accessManager = ProviderLoader.configure(authConfig, provider, StingrayAccessManagerFactory.class);
        return accessManager;
    }

    StingraySecurityFilter createSecurityFilter() {
        StingrayAuthenticationManager authenticationManager = application.get(StingrayAuthenticationManager.class);
        StingrayAccessManager accessManager = application.get(StingrayAccessManager.class);
        return new StingraySecurityFilter(authenticationManager, accessManager, this::getJaxRsRoutingEndpoint);
    }

    Method getJaxRsRoutingEndpoint(ContainerRequestContext requestContext) {
        Request request = requestContext.getRequest();
        ContainerRequest containerRequest = (ContainerRequest) request;
        RoutingContext routingContext = (RoutingContext) containerRequest.getUriInfo();
        Method resourceMethod = routingContext.getResourceMethod();
        return resourceMethod;
    }
}
