package no.cantara.stingray.application;

import jakarta.servlet.DispatcherType;
import jakarta.servlet.Filter;
import no.cantara.config.ApplicationProperties;

import java.util.EnumSet;
import java.util.function.Supplier;

public interface StingrayApplication<A extends StingrayApplication> extends StingrayRegistry {

    String alias();

    ApplicationProperties config();

    A init();

    boolean isInitialized();

    default <T extends Filter> T initAndAddServletFilter(Class<T> clazz, Supplier<T> filterSupplier, String pathSpec, EnumSet<DispatcherType> dispatches) {
        return initAndAddServletFilter(clazz.getName(), filterSupplier, pathSpec, dispatches);
    }

    <T extends Filter> T initAndAddServletFilter(String key, Supplier<T> filterSupplier, String pathSpec, EnumSet<DispatcherType> dispatches);

    default <T> T initAndRegisterJaxRsWsComponent(Class<T> clazz, Supplier<T> init) {
        return initAndRegisterJaxRsWsComponent(clazz.getName(), init);
    }

    <T> T initAndRegisterJaxRsWsComponent(String key, Supplier<T> init);

    default <T> T init(Class<T> clazz, Supplier<T> init) {
        return init(clazz.getName(), init);
    }

    <T> T init(String key, Supplier<T> init);

    default A override(Class<?> clazz, Supplier<Object> init) {
        return override(clazz.getName(), init);
    }

    A override(String key, Supplier<Object> init);

    A start(boolean alsoRunPostInitAfterStart);

    A start();

    A postInit();

    A stop();

    int getBoundPort();

    String contextPath();
}
