package no.cantara.stingray.sample.greeter;

import com.codahale.metrics.MetricRegistry;
import no.cantara.config.ApplicationProperties;
import no.cantara.stingray.application.AbstractStingrayApplication;
import no.cantara.stingray.application.StingrayApplication;
import no.cantara.stingray.application.health.StingrayHealthService;
import no.cantara.stingray.security.StingraySecurity;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;

public class GreeterApplication extends AbstractStingrayApplication<GreeterApplication> {

    private static final Logger log = LoggerFactory.getLogger(GreeterApplication.class);

    public static void main(String[] args) {
        ApplicationProperties config = new GreeterApplicationFactory()
                .conventions(ApplicationProperties.builder())
                .build();
        new GreeterApplication(config).init().start();
    }

    public GreeterApplication(ApplicationProperties config) {
        super("greeter",
                readMetaInfMavenPomVersion("no.cantara.stingray", "greeter"),
                config
        );
    }

    @Override
    public void doInit() {
        initBuiltinDefaults();
        StingraySecurity.initSecurity(this, this::customAccessManagerSecurity);
        init(GreetingCandidateRepository.class, this::createGreetingCandidateRepository);
        init(RandomizerClient.class, this::createHttpRandomizer);
        init(GreetingService.class, this::createGreetingService);
        GreetingResource greetingResource = initAndRegisterJaxRsWsComponent(GreetingResource.class, this::createGreetingResource);
        get(StingrayHealthService.class).registerHealthProbe("greeting.request.count", greetingResource::getRequestCount);
    }

    private void customAccessManagerSecurity(StingrayApplication application, ApplicationProperties.Builder builder) {
        StingraySecurity.defaultAccessManagerConfig(application, builder);
        builder.enableSystemProperties("access-manager.")
                .enableEnvironmentVariables("ACCESS_MANAGER_");
    }

    private GreetingCandidateRepository createGreetingCandidateRepository() {
        return new DefaultGreetingCandidateRepository(List.of("Hello", "Yo", "Hola", "Hei"));
    }

    private HttpRandomizerClient createHttpRandomizer() {
        String randomizerHost = config.get("randomizer.host");
        int randomizerPort = config.asInt("randomizer.port");
        return new HttpRandomizerClient("http://" + randomizerHost + ":" + randomizerPort + "/randomizer");
    }

    private GreetingService createGreetingService() {
        RandomizerClient randomizerClient = get(RandomizerClient.class);
        GreetingCandidateRepository greetingCandidateRepository = get(GreetingCandidateRepository.class);
        MetricRegistry metricRegistry = get(MetricRegistry.class);
        return new GreetingService(metricRegistry, greetingCandidateRepository, randomizerClient);
    }

    private GreetingResource createGreetingResource() {
        GreetingService greetingService = get(GreetingService.class);
        return new GreetingResource(greetingService);
    }
}
