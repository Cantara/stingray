# Stingray

## Purpose
Application framework based on Servlets, Jetty, and Jakarta RS (JAX-RS) with Jersey. Provides a structured foundation for building web services with built-in support for Dropwizard Metrics, CPU profiling, and health endpoints.

## Tech Stack
- Language: Java 11+
- Framework: Jetty, Jersey (Jakarta RS), Servlet API
- Build: Maven (multi-module POM)
- Key dependencies: Dropwizard Metrics, Jetty, Jersey, SLF4J

## Architecture
Multi-module Maven project providing a layered application framework. Includes servlet infrastructure, JAX-RS resource support, metrics collection (Dropwizard Metrics), and CPU profiling capabilities (pprof integration). Designed as a foundation framework that other Cantara services build upon.

## Key Entry Points
- Multi-module POM structure
- Metrics endpoint: `http://localhost:8362/admin/pprof`
- `pom.xml` - Maven coordinates: `no.cantara.stingray:stingray-project`

## Development
```bash
# Build
mvn clean install

# Test
mvn test

# CPU profiling (when running a Stingray-based app)
curl "http://localhost:8362/admin/pprof?duration=10" > prof
pprof --pdf prof > profile.pdf
```

## Domain Context
Application framework for Cantara microservices. Provides the foundational web service infrastructure (Jetty, Jersey, metrics) used by several Cantara services as an alternative to Spring Boot.
