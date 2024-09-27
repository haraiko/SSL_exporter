package main

import (
    "bufio"
    "flag"
    "fmt"
    "log"
    "os"
    "os/exec"
    "strings"
    "time"

    "github.com/prometheus/client_golang/prometheus"
    "github.com/prometheus/client_golang/prometheus/promhttp"
    "net/http"
)

// Metrics for start and expiry dates of SSL certificates
var (
    certStart = prometheus.NewGaugeVec(
        prometheus.GaugeOpts{
            Name: "cert_start",
            Help: "Start date of SSL certificates in Unix timestamp",
        },
        []string{"domain"},
    )
    certExpiry = prometheus.NewGaugeVec(
        prometheus.GaugeOpts{
            Name: "cert_expiry",
            Help: "Expiry date of SSL certificates in Unix timestamp",
        },
        []string{"domain"},
    )
)

func init() {
    prometheus.MustRegister(certStart)
    prometheus.MustRegister(certExpiry)
}

// getSSLCertDates executes the OpenSSL command to fetch the start and expiry dates of the certificate
func getSSLCertDates(domain string) (start, expiry time.Time, err error) {
    cmd := fmt.Sprintf(`openssl s_client -connect %s:443 -servername %s < /dev/null 2>/dev/null | openssl x509 -noout -dates`, domain, domain)
    output, err := exec.Command("bash", "-c", cmd).Output()
    if err != nil {
        return start, expiry, err
    }

    lines := strings.Split(string(output), "\n")
    for _, line := range lines {
        if strings.HasPrefix(line, "notBefore=") {
            start, err = time.Parse("Jan 2 15:04:05 2006 MST", strings.TrimPrefix(line, "notBefore="))
            if err != nil {
                return start, expiry, err
            }
        } else if strings.HasPrefix(line, "notAfter=") {
            expiry, err = time.Parse("Jan 2 15:04:05 2006 MST", strings.TrimPrefix(line, "notAfter="))
            if err != nil {
                return start, expiry, err
            }
        }
    }
    return start, expiry, nil
}

// readDomains reads the list of domains from a configuration file
func readDomains(filePath string) ([]string, error) {
    file, err := os.Open(filePath)
    if err != nil {
        return nil, err
    }
    defer file.Close()

    var domains []string
    scanner := bufio.NewScanner(file)
    for scanner.Scan() {
        line := strings.TrimSpace(scanner.Text())
        if line != "" && !strings.HasPrefix(line, "#") { // Ignore empty lines and comments
            domains = append(domains, line)
        }
    }
    if err := scanner.Err(); err != nil {
        return nil, err
    }
    return domains, nil
}

// updateMetrics updates the Prometheus metrics for each domain
func updateMetrics(domains []string) {
    for _, domain := range domains {
        start, expiry, err := getSSLCertDates(domain)
        if err != nil {
            log.Printf("Error fetching SSL certificate for domain %s: %v", domain, err)
            continue
        }

        certStart.With(prometheus.Labels{"domain": domain}).Set(float64(start.Unix()))
        certExpiry.With(prometheus.Labels{"domain": domain}).Set(float64(expiry.Unix()))

        log.Printf("Updated metrics for domain %s: Start=%v, Expiry=%v", domain, start, expiry)
    }
}

func main() {
    var (
        listenAddress = flag.String("listen-address", ":8837", "The address to listen on for HTTP requests.")
        configPath    = flag.String("config", "domains.cfg", "Path to the domains configuration file.")
    )
    flag.Parse()

    // Read domains from the configuration file
    domains, err := readDomains(*configPath)
    if err != nil {
        log.Fatalf("Failed to read domains from config file: %v", err)
    }

    // Initial update of metrics
    updateMetrics(domains)

    // Periodically update the metrics every 6 hours
    go func() {
        for {
            time.Sleep(6 * time.Hour)
            updateMetrics(domains)
        }
    }()

    // Start HTTP server for Prometheus metrics
    http.Handle("/metrics", promhttp.Handler())
    log.Printf("Starting server on %s", *listenAddress)
    log.Fatal(http.ListenAndServe(*listenAddress, nil))
}
