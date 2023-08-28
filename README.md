# Stingray

![GitHub tag (latest SemVer)](https://img.shields.io/github/v/tag/Cantara/Stingray) ![Build Status](https://jenkins.cantara.no/buildStatus/icon?job=Stingray) ![GitHub commit activity](https://img.shields.io/github/commit-activity/m/Cantara/Stingray) [![Project Status: Active – The project has reached a stable, usable state and is being actively developed.](http://www.repostatus.org/badges/latest/active.svg)](http://www.repostatus.org/#active)  [![Known Vulnerabilities](https://snyk.io/test/github/Cantara/Stingray/badge.svg)](https://snyk.io/test/github/Cantara/Stingray)

Application framework based on Servlets, Jetty, Javax/Jakarta RsWs, Jersey

# Dropwizard Metrics

Documentation: https://metrics.dropwizard.io/4.2.0/index.html

## Cpu Profiler

### Prerequisites

#### MacOS
1. Install `pprof` command: `brew install gperftools`
2. Install `ps2pdf` command: `brew install ghostscript`

#### Amazon Linux AMI
TODO

### Creating a performance profile pdf report
1. Get performance profile data: `curl "http://localhost:8362/admin/pprof?duration=10" > prof`
2. Create pdf from profile data: `pprof --pdf prof > profile.pdf`
