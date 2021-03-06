package no.cantara.stingray.sample.greeter;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.inject.Inject;
import no.cantara.stingray.application.StingrayApplication;
import no.cantara.stingray.application.StingrayLogging;
import no.cantara.stingray.security.authentication.test.FakeStingrayAuthorization;
import no.cantara.stingray.test.StingrayBeforeInitLifecycleListener;
import no.cantara.stingray.test.StingrayTestClient;
import no.cantara.stingray.test.StingrayTestExtension;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertTrue;

@ExtendWith(StingrayTestExtension.class)
public class GreetingTest implements StingrayBeforeInitLifecycleListener {

    static {
        StingrayLogging.init();
    }

    private static final Logger log = LoggerFactory.getLogger(GreetingTest.class);

    private static final ObjectMapper mapper = new ObjectMapper();

    @Inject
    StingrayTestClient testClient;

    @Override
    public void beforeInit(StingrayApplication application) {
        application.override(RandomizerClient.class, () -> RandomizerClientMock.createMockRandomizer(application));
    }

    @Test
    public void thatGreetingCanBeTestedByItself() {
        Greeting greeting = testClient.get()
                .path("/greet/John")
                .authorization(FakeStingrayAuthorization.user()
                        .userId("userid-1")
                        .username("john")
                        .customerRef("creftojohn")
                        .build())
                .execute()
                .expect200Ok()
                .contentAsType(Greeting.class);
        log.info("/greet/John Response: {}", greeting);
        JsonNode body = testClient.get()
                .path("/health")
                .execute()
                .expect200Ok()
                .contentAsType(JsonNode.class);
        log.info("/health Response: {}", body.toPrettyString());
    }

    @Test
    public void thatOpenApiWorks() {
        String openApiYaml = testClient.get()
                .path("/openapi.yaml")
                .execute()
                .expect200Ok()
                .contentAsString();
        log.info("/openapi.yaml:\n{}", openApiYaml);
    }

    @Test
    public void thatAdminHealthCheckServletWorks() throws JsonProcessingException {
        String body = testClient.get()
                .path("/admin/healthcheck")
                .execute()
                .expect200Ok()
                .contentAsString();
        log.info("/admin/healthcheck Response:\n{}", mapper.readValue(body, JsonNode.class).toPrettyString());
    }

    @Test
    public void thatAdminMetricsServletWorks() throws JsonProcessingException, InterruptedException {
        for (int i = 0; i < 50; i++) {
            int remainder = i % 4;
            if (remainder == 0) {
                testClient.get()
                        .path("/admin/ping")
                        .execute()
                        .expect200Ok();
            } else if (remainder == 1) {
                testClient.get()
                        .path("/admin/healthcheck")
                        .execute()
                        .expect200Ok();
            } else if (remainder == 2) {
                testClient.get()
                        .path("/greet/John")
                        .authorization(FakeStingrayAuthorization.application()
                                .applicationId("junit-viewer")
                                .build())
                        .execute()
                        .expect200Ok();
            } else {
                // remainder == 3
                testClient.get()
                        .path("/openapi.yaml")
                        .execute()
                        .expect200Ok();
            }
        }
        String body = testClient.get()
                .path("/admin/metrics/jersey")
                .execute()
                .expect200Ok()
                .contentAsString();
        log.info("/admin/metrics/jersey Response:\n{}", mapper.readValue(body, JsonNode.class).toPrettyString());
    }

    @Test
    public void thatAdminPingServletWorks() {
        String body = testClient.get()
                .path("/admin/ping")
                .execute()
                .expect200Ok()
                .contentAsString();
        log.info("/admin/ping Response: '{}'", body);
    }

    @Test
    public void thatAdminThreadsServletWorks() {
        String body = testClient.get()
                .path("/admin/threads")
                .execute()
                .expect200Ok()
                .contentAsString();
        log.info("/admin/threads Response:\n{}", body);
    }

    @Test
    public void thatAdminCpuProfileServletWorks() {
        ByteBuffer buf = testClient.get()
                .path("/admin/pprof")
                .query("duration", "1")
                .execute()
                .expect200Ok()
                .contentAsType(ByteBuffer.class);
        assertTrue(buf.limit() > 0);
        System.out.printf("Bytes in body: %d%n", buf.limit());
    }

    @Test
    public void postBodyJsonString() {
        testClient.post()
                .path("/greet")
                .authorization(FakeStingrayAuthorization.application()
                        .applicationId("junit-admin")
                        .build())
                .bodyJson("{\"greeting\": \"How do you do?\"}")
                .execute()
                .expect204NoContent();
    }

    @Test
    public void postBodyJsonPojo() {
        testClient.post()
                .path("/greet")
                .authorization(FakeStingrayAuthorization.application()
                        .applicationId("junit-admin")
                        .build())
                .bodyJson(new GreetingCandidate("Good morning"))
                .execute()
                .expect204NoContent();
    }

    @Test
    public void postBodyJsonFile() {
        testClient.post()
                .path("/greet")
                .authorization(FakeStingrayAuthorization.application()
                        .applicationId("junit-admin")
                        .build())
                .bodyJson(Path.of("src/test/resources/greeting-candidates/candidate-1.json").toFile())
                .execute()
                .expect204NoContent();
    }

    @Test
    public void postBodyJsonInputStream() {
        testClient.post()
                .path("/greet")
                .authorization(FakeStingrayAuthorization.application()
                        .applicationId("junit-admin")
                        .build())
                .bodyJson(getClass().getResourceAsStream("/greeting-candidates/candidate-2.json"))
                .execute()
                .expect204NoContent();
    }

    @Test
    public void postBodyJsonBytes() throws IOException {
        testClient.post()
                .path("/greet")
                .authorization(FakeStingrayAuthorization.application()
                        .applicationId("junit-admin")
                        .build())
                .bodyJson(Files.readAllBytes(Path.of("src/test/resources/greeting-candidates/candidate-3.json")))
                .execute()
                .expect204NoContent();
    }

    @Test
    public void listGreetingCandidatesAsString() throws JsonProcessingException {
        String body = testClient.get()
                .path("/greet/candidates")
                .authorization(FakeStingrayAuthorization.application()
                        .applicationId("junit-viewer")
                        .build())
                .execute()
                .expect200Ok()
                .contentAsString();
        List<GreetingCandidate> greetingCandidates = mapper.readValue(body, new TypeReference<>() {
        });
        assertTrue(greetingCandidates.size() > 0);
    }

    @Test
    public void listGreetingCandidatesAsTypeReferece() {
        List<GreetingCandidate> greetingCandidates = testClient.get()
                .path("/greet/candidates")
                .authorization(FakeStingrayAuthorization.application()
                        .applicationId("junit-viewer")
                        .build())
                .execute()
                .expect200Ok()
                .contentAsType(new TypeReference<>() {
                });
        assertTrue(greetingCandidates.size() > 0);
    }

    @Test
    public void listGreetingCandidatesAsListOf() {
        List<GreetingCandidate> greetingCandidates = testClient.get()
                .path("/greet/candidates")
                .authorization(FakeStingrayAuthorization.application()
                        .applicationId("junit-viewer")
                        .build())
                .execute()
                .expect200Ok()
                .contentAsList(GreetingCandidate.class);
        assertTrue(greetingCandidates.size() > 0);
    }

    @Test
    public void listGreetingCandidatesAsArray() {
        GreetingCandidate[] greetingCandidates = testClient.get()
                .path("/greet/candidates")
                .authorization(FakeStingrayAuthorization.application()
                        .applicationId("junit-viewer")
                        .build())
                .execute()
                .expect200Ok()
                .contentAsType(GreetingCandidate[].class);
        assertTrue(greetingCandidates.length > 0);
    }

    @Test
    public void listGreetingCandidatesAsJsonNode() {
        JsonNode node = testClient.get()
                .path("/greet/candidates")
                .authorization(FakeStingrayAuthorization.application()
                        .applicationId("junit-viewer")
                        .build())
                .execute()
                .expect200Ok()
                .contentAsType(JsonNode.class);
        List<GreetingCandidate> greetingCandidates = mapper.convertValue(node, new TypeReference<>() {
        });
        assertTrue(greetingCandidates.size() > 0);
    }

    @Test
    public void listGreetingCandidatesAsInputStream() throws IOException {
        try (InputStream is = testClient.get()
                .path("/greet/candidates")
                .authorization(FakeStingrayAuthorization.application()
                        .applicationId("junit-viewer")
                        .build())
                .execute()
                .expect200Ok()
                .content();
        ) {
            List<GreetingCandidate> greetingCandidates = mapper.readValue(is, new TypeReference<>() {
            });
            assertTrue(greetingCandidates.size() > 0);
        }
    }
}