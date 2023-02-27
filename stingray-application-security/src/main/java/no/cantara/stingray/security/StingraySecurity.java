package no.cantara.stingray.security;

import no.cantara.config.ApplicationProperties;
import no.cantara.stingray.application.StingrayApplication;

import java.util.function.BiConsumer;

public class StingraySecurity {

    public static void initSecurity(StingrayApplication application) {
        initSecurity(application, StingraySecurity::defaultAccessManagerConfig);
    }

    public static void initSecurity(StingrayApplication application, BiConsumer<StingrayApplication, ApplicationProperties.Builder> configBuilder) {
        StingraySecurityInitializationHelper helper = new StingraySecurityInitializationHelper(application, configBuilder);
        helper.initSecurity();
    }

    /**
     * Will apply default access-manager config to the ApplicationProperties.Builder.
     *
     * @param builder
     */
    public static void defaultAccessManagerConfig(StingrayApplication application, ApplicationProperties.Builder builder) {
        String applicationAlias = application.alias();
        builder.classpathPropertiesFile(applicationAlias + "/service-authorization.properties")
                .classpathPropertiesFile(applicationAlias + "/authorization.properties")
                .classpathPropertiesFile(applicationAlias + "-authorization.properties")
                .classpathPropertiesFile("authorization-" + applicationAlias + ".properties")
                .filesystemPropertiesFile("authorization.properties")
                .filesystemPropertiesFile(applicationAlias + "-authorization.properties")
                .filesystemPropertiesFile("authorization-" + applicationAlias + ".properties")
        ;
    }
}
