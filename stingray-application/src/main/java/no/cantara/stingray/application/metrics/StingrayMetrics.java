package no.cantara.stingray.application.metrics;

import com.codahale.metrics.Gauge;
import com.codahale.metrics.MetricRegistry;
import com.codahale.metrics.jersey3.MetricsFeature;
import com.codahale.metrics.jvm.BufferPoolMetricSet;
import com.codahale.metrics.jvm.ClassLoadingGaugeSet;
import com.codahale.metrics.jvm.GarbageCollectorMetricSet;
import com.codahale.metrics.jvm.JvmAttributeGaugeSet;
import com.codahale.metrics.jvm.MemoryUsageGaugeSet;
import com.codahale.metrics.jvm.ThreadStatesGaugeSet;
import no.cantara.stingray.application.StingrayApplication;

import java.lang.management.ManagementFactory;

public class StingrayMetrics {

    final StingrayApplication application;

    public StingrayMetrics(StingrayApplication application) {
        this.application = application;
    }

    public void initAllMetrics() {
        initBaseAndAppMetrics();
        initJettyMetrics();
        initJerseyMetrics();
        initJvmMetrics();
    }

    public MetricRegistry initBaseAndAppMetrics() {
        MetricRegistry appMetricRegistry = (MetricRegistry) application.init(MetricRegistry.class, MetricRegistry::new);
        appMetricRegistry.register("name", (Gauge<String>) application::alias);
        MetricRegistry baseMetricRegistry = (MetricRegistry) application.init("metrics.base", MetricRegistry::new);
        baseMetricRegistry.register("app", appMetricRegistry);
        return appMetricRegistry;
    }

    public void initJerseyMetrics() {
        MetricRegistry metricRegistry = (MetricRegistry) application.get("metrics.base");
        MetricRegistry jerseyMetricRegistry = (MetricRegistry) application.init("metrics.jersey", MetricRegistry::new);
        metricRegistry.register("jersey", jerseyMetricRegistry);
        application.initAndRegisterJaxRsWsComponent(MetricsFeature.class, () -> new MetricsFeature(jerseyMetricRegistry));
    }

    public void initJettyMetrics() {
        MetricRegistry metricRegistry = (MetricRegistry) application.get("metrics.base");
        MetricRegistry jettyMetricRegistry = (MetricRegistry) application.init("metrics.jetty", MetricRegistry::new);
        metricRegistry.register("jetty", jettyMetricRegistry);
    }

    public void initJvmMetrics() {
        MetricRegistry metricRegistry = (MetricRegistry) application.get("metrics.base");
        MetricRegistry jvmMetricRegistry = (MetricRegistry) application.init("metrics.jvm", MetricRegistry::new);
        jvmMetricRegistry.registerAll("memory", new MemoryUsageGaugeSet());
        jvmMetricRegistry.registerAll("threads", new ThreadStatesGaugeSet());
        // jvmMetricRegistry.registerAll("threads", new CachedThreadStatesGaugeSet(5, TimeUnit.SECONDS));
        jvmMetricRegistry.registerAll("runtime", new JvmAttributeGaugeSet());
        jvmMetricRegistry.registerAll("gc", new GarbageCollectorMetricSet());
        jvmMetricRegistry.register("fd", new StingrayFileDescriptorMetricSet());
        jvmMetricRegistry.register("classes", new ClassLoadingGaugeSet());
        jvmMetricRegistry.registerAll("buffers", new BufferPoolMetricSet(ManagementFactory.getPlatformMBeanServer()));
        metricRegistry.register("jvm", jvmMetricRegistry);
    }
}
