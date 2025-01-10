package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"html"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/sirupsen/logrus"
	"golang.org/x/time/rate"
	"gopkg.in/yaml.v3"
)

var log = logrus.New()

type Result struct {
	SiteURL        string              `json:"site_url"`
	Title          string              `json:"title,omitempty"`
	Vulnarbilities []map[string]string `json:"vulnarbilities,omitempty"`
	ServerHeader   string              `json:"server,omitempty"`
	XPoweredBy     string              `json:"powered_by,omitempty"`
	StartTime      time.Time           `json:"start_time"`
	EndTime        time.Time           `json:"end_time"`
}

type WPVulnScanner struct {
	Vulnarbilities     WPVulnerabilities
	concurrencyLimiter *ConcurrencyLimiter
	fetcher            *Fetcher
}

// NewWPVulnScanner создает новый WPVulnScanner с использованием Functional Options
func NewWPVulnScanner(Vulnarbilities WPVulnerabilities, options ...WPVulnScannerOption) *WPVulnScanner {
	// Настройки по умолчанию
	config := &WPVulnScannerConfig{
		MaxConcurrent: 10,
		LogLevel:      "info",
	}

	// Применяем переданные опции
	for _, option := range options {
		option(config)
	}

	// Настройка логгера
	setupLogger(config.LogLevel)

	return &WPVulnScanner{
		Vulnarbilities:     Vulnarbilities,
		concurrencyLimiter: NewConcurrencyLimiter(config.MaxConcurrent),
		fetcher:            NewFetcher(config.FetchConfig),
	}
}

// WPVulnScannerConfig содержит конфигурацию для WPVulnScanner
type WPVulnScannerConfig struct {
	MaxConcurrent  int
	LogLevel       string
	FetchConfig    FetchConfig
	Vulnarbilities WPVulnerabilities
}

// WPVulnScannerOption определяет тип функции для настройки WPVulnScanner
type WPVulnScannerOption func(*WPVulnScannerConfig)

// WithMaxConcurrent устанавливает максимальное количество concurrent запросов
func WithMaxConcurrent(maxConcurrent int) WPVulnScannerOption {
	return func(c *WPVulnScannerConfig) {
		c.MaxConcurrent = maxConcurrent
	}
}

// WithLogLevel устанавливает уровень логирования
func WithLogLevel(logLevel string) WPVulnScannerOption {
	return func(c *WPVulnScannerConfig) {
		c.LogLevel = logLevel
	}
}

// WithFetchConfig устанавливает конфигурацию для Fetcher
func WithFetchConfig(fetchConfig FetchConfig) WPVulnScannerOption {
	return func(c *WPVulnScannerConfig) {
		c.FetchConfig = fetchConfig
	}
}

// WithVulnarbilities устанавливает уязвимые плагины
func WithVulnarbilities(Vulnarbilities WPVulnerabilities) WPVulnScannerOption {
	return func(c *WPVulnScannerConfig) {
		c.Vulnarbilities = Vulnarbilities
	}
}

func (s *WPVulnScanner) Scan(urls []string, results chan Result) {
	startTime := time.Now()
	for _, u := range urls {
		u = ensureScheme(u)
		uj, err := urlJoin(u, "/")

		if err != nil {
			log.Warnf("❗ Invalid URL %s: %v", u, err)
			continue
		}

		s.concurrencyLimiter.Acquire()
		go s.processURL(uj, results)
	}

	s.concurrencyLimiter.Wait()
	close(results)

	log.Infof("🏁 Scanning completed in %.3fs", time.Since(startTime).Seconds())
}

// Vulnerability описывает информацию об уязвимости плагина.
type WPVulnerability struct {
	CveId       string `yaml:"cve_id" toml:"cve_id"`                               // Идентификатор CVE
	ProductName string `yaml:"product_name" toml:"product_name"`                   // Название продукта (плагина или темы)
	ProductType string `yaml:"product_type" toml:"product_type"`                   // Тип продукта: "plugin" или "theme"
	MinVersion  string `yaml:"min_version,omitempty" toml:"min_version,omitempty"` // Минимальная версия (опционально)
	MaxVersion  string `yaml:"max_version" toml:"max_version"`                     // Максимальная версия
}

// WPVulnerabilities хранит список уязвимостей.
type WPVulnerabilities []WPVulnerability

var wpVulnerabilities = WPVulnerabilities{
	// https://xakep.ru/2024/08/22/litespeed-cache-new-admin/
	{
		CveId:       "CVE-2024-28000",
		ProductName: "litespeed-cache",
		ProductType: "plugin",
		MaxVersion:  "6.3.0.1",
	},
	// https://www.kaspersky.com/blog/cve-2024-10924-wordpress-authentication-bypass/52637/
	{
		CveId:       "CVE-2024-10924",
		ProductName: "really-simple-ssl",
		ProductType: "plugin",
		MinVersion:  "9.0.0",
		MaxVersion:  "9.1.1.1",
	},
	// https://censys.com/cve-2024-27956/
	{
		CveId:       "CVE-2024-27956",
		ProductName: "wp-automatic",
		ProductType: "plugin",
		MaxVersion:  "3.92.0",
	},
	{
		CveId:       "CVE-2024-10542",
		ProductName: "cleantalk-spam-protect",
		ProductType: "plugin",
		MaxVersion:  "6.43.2",
	},
	// https://github.com/advisories/GHSA-wrj5-h97x-2xcg
	{
		CveId:       "CVE-2024-10215",
		ProductName: "wpbookit",
		ProductType: "plugin",
		MaxVersion:  "1.6.4",
	},
	{
		CveId:       "CVE-2024-11613",
		ProductName: "wp-file-upload",
		ProductType: "plugin",
		MaxVersion:  "4.24.15",
	},
	// https://www.wordfence.com/blog/2024/01/type-juggling-leads-to-two-vulnerabilities-in-post-smtp-mailer-wordpress-plugin/
	{
		CveId:       "CVE-2023-6875",
		ProductName: "post-smtp",
		ProductType: "plugin",
		MaxVersion:  "2.8.7",
	},
	// https://github.com/gbrsh/CVE-2024-1071
	{
		CveId:       "CVE-2024-1071",
		ProductName: "ultimate-member",
		ProductType: "plugin",
		MinVersion:  "2.1.3",
		MaxVersion:  "2.8.2",
	},
	// https://thehackernews.com/2024/08/givewp-wordpress-plugin-vulnerability.html
	{
		CveId:       "CVE-2024-5932",
		ProductName: "give",
		ProductType: "plugin",
		MaxVersion:  "3.14.1",
	},
	// https://www.techradar.com/pro/security/millions-at-risk-as-popular-wordpress-database-plugin-is-targeted-by-hackers-heres-what-wordpress-site-owners-need-to-know
	{
		CveId:       "CVE-2023-6933",
		ProductName: "better-search-replace",
		ProductType: "plugin",
		MaxVersion:  "1.4.4",
	},
	// https://www.cdnetworks.com/blog/cloud-computing/backup-migration-plugin-vulnerability/
	// https://github.com/Chocapikk/CVE-2023-6553/blob/main/exploit.py
	{
		CveId:       "CVE-2023-6553",
		ProductName: "backup-backup",
		ProductType: "plugin",
		MaxVersion:  "1.3.7",
	},
	// Древняя уязвимость
	// https://nvd.nist.gov/vuln/detail/cve-2020-35489
	{
		CveId:       "CVE-2020-35489",
		ProductName: "contact-form-7",
		ProductType: "plugin",
		MaxVersion:  "3.5.1",
	},
	// https://github.com/mansoorr123/wp-file-manager-CVE-2020-25213
	{
		CveId:       "CVE-2020-25213",
		ProductName: "wp-file-manager",
		ProductType: "plugin",
		MinVersion:  "6.0",
		MaxVersion:  "6.8",
	},
}

func loadVulnarbilitiesFromFile(filePath string) (WPVulnerabilities, error) {
	var Vulnarbilities WPVulnerabilities
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	if strings.HasSuffix(filePath, ".yaml") || strings.HasSuffix(filePath, ".yml") {
		if err := yaml.NewDecoder(file).Decode(&Vulnarbilities); err != nil {
			return nil, err
		}
	} else if strings.HasSuffix(filePath, ".toml") {
		if _, err := toml.DecodeReader(file, &Vulnarbilities); err != nil {
			return nil, err
		}
	} else {
		return nil, fmt.Errorf("unsupported file format")
	}

	return Vulnarbilities, nil
}

func (s *WPVulnScanner) processURL(targetUrl string, results chan<- Result) {
	defer s.concurrencyLimiter.Release()

	startTime := time.Now()
	body, status, headers, err := s.fetcher.Fetch(targetUrl)
	if err != nil {
		log.Errorf("⛔ Error fetching %s: %v", targetUrl, err)
		return
	}

	if status != 200 {
		log.Errorf("⛔ Bad status code for %s: %d", targetUrl, status)
		return
	}

	mimeType := getMimeType(headers)
	if mimeType != "text/html" {
		log.Errorf("⛔ Invalid mime type for %s: %s", targetUrl, mimeType)
		return
	}

	content := string(body)

	if !strings.Contains(content, "/wp-content/") {
		log.Debugf("⛔ It's not a WordPress site: %s", targetUrl)
		return
	}

	title := extractTitle(content)

	var wg sync.WaitGroup
	var mu sync.Mutex
	vulnarbilities := make([]map[string]string, 0)
	for _, v := range s.Vulnarbilities {
		s.concurrencyLimiter.Acquire()
		wg.Add(1)
		go func(vuln WPVulnerability) {
			defer func() {
				s.concurrencyLimiter.Release()
				wg.Done()
			}()
			readmeUrl, _ := urlJoin(targetUrl, fmt.Sprintf("/wp-content/%ss/%s/readme.txt", vuln.ProductType, vuln.ProductName))
			body, status, _, err := s.fetcher.Fetch(readmeUrl)
			if err != nil {
				log.Debugf("⛔ Error fetching %s: %v", readmeUrl, err)
				return
			}
			if status != 200 {
				log.Debugf("⛔ Bad status code for %s: %d", readmeUrl, status)
				return
			}
			content := string(body)
			re := regexp.MustCompile(`(?m)^Stable tag: (.*)$`)
			matches := re.FindStringSubmatch(content)
			if len(matches) < 2 {
				log.Errorf("⛔ Version not found for %s", readmeUrl)
				return
			}

			versionStr := matches[1]

			log.Debugf("Found version %s for %s", versionStr, readmeUrl)

			version := versionToNumber(versionStr)
			minVersion := versionToNumber(vuln.MinVersion)
			maxVersion := versionToNumber(vuln.MaxVersion)

			log.Debugf("version=%#08x (%s), minVersion=%#08x (%s), maxVersion=%#08x (%s)", version, versionStr, minVersion, vuln.MinVersion, maxVersion, vuln.MaxVersion)

			if version >= minVersion && version <= maxVersion {
				log.Infof("✅ Vulnerability %s found in %s %q (version %s) at %s", vuln.CveId, vuln.ProductType, vuln.ProductName, versionStr, readmeUrl)

				mu.Lock()
				vulnarbilities = append(vulnarbilities, map[string]string{
					"product_name": vuln.ProductName,
					"product_type": vuln.ProductType,
					"version":      matches[1],
					"cve_id":       vuln.CveId,
				})
				mu.Unlock()
			}
		}(v)
	}

	wg.Wait()

	if len(vulnarbilities) == 0 {
		return
	}

	results <- Result{
		SiteURL:        targetUrl,
		Title:          title,
		Vulnarbilities: vulnarbilities,
		ServerHeader:   headers.Get("Server"),
		XPoweredBy:     headers.Get("X-Powered-By"),
		StartTime:      startTime,
		EndTime:        time.Now(),
	}
}

type ConcurrencyLimiter struct {
	wg  sync.WaitGroup
	sem chan struct{}
}

func NewConcurrencyLimiter(maxConcurrent int) *ConcurrencyLimiter {
	return &ConcurrencyLimiter{
		sem: make(chan struct{}, maxConcurrent),
	}
}

func (cl *ConcurrencyLimiter) Acquire() {
	cl.sem <- struct{}{}
	cl.wg.Add(1)
}

func (cl *ConcurrencyLimiter) Release() {
	<-cl.sem
	cl.wg.Done()
}

func (cl *ConcurrencyLimiter) Wait() {
	cl.wg.Wait()
	close(cl.sem)
}

type Fetcher struct {
	client         *http.Client
	delay          time.Duration
	requestTimeout time.Duration
	rateLimiter    *rate.Limiter
}

// FetchConfig содержит конфигурацию для Fetcher
type FetchConfig struct {
	Timeout        time.Duration
	RequestTimeout time.Duration
	Delay          time.Duration
	DNSServer      string
	DNSProto       string
}

func NewFetcher(config FetchConfig) *Fetcher {
	var resolver *net.Resolver
	if config.DNSServer == "" {
		// Используем системный DNS, если не задан
		resolver = net.DefaultResolver
	} else {
		log.Debugf("Using DNS server %s/%s", config.DNSServer, config.DNSProto)

		resolver = &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				d := net.Dialer{
					Timeout: time.Second * 5,
				}
				return d.DialContext(ctx, config.DNSProto, config.DNSServer)
			},
		}
	}

	// Настройка TLS для отключения проверки сертификата
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true, // Отключаем проверку сертификата
	}

	transport := &http.Transport{
		DialContext: (&net.Dialer{
			Resolver:  resolver,
			Timeout:   config.Timeout,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		TLSClientConfig: tlsConfig, // Применяем настройки TLS
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   config.Timeout,
	}

	rateLimiter := rate.NewLimiter(rate.Every(config.Delay), 1)

	return &Fetcher{
		client:         client,
		delay:          config.Delay,
		requestTimeout: config.RequestTimeout,
		rateLimiter:    rateLimiter,
	}
}

func (f *Fetcher) Fetch(targetUrl string) ([]byte, int, http.Header, error) {
	log.Debugf("Fetch URL: %s", targetUrl)

	ctx, cancel := context.WithTimeout(context.Background(), f.requestTimeout)
	defer cancel()

	if err := f.rateLimiter.Wait(ctx); err != nil {
		return nil, 0, nil, fmt.Errorf("rate limiter error: %v", err)
	}

	req, err := http.NewRequestWithContext(ctx, "GET", targetUrl, nil)
	if err != nil {
		return nil, 0, nil, fmt.Errorf("failed to create request: %v", err)
	}

	f.setHeaders(req)

	resp, err := f.client.Do(req)
	if err != nil {
		return nil, 0, nil, fmt.Errorf("request failed: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, 0, nil, fmt.Errorf("failed to read response body: %v", err)
	}

	//log.Debugf("%d %s", resp.StatusCode, targetUrl)

	return body, resp.StatusCode, resp.Header, nil
}

func (f *Fetcher) setHeaders(req *http.Request) {
	headers := map[string]string{
		"Accept":                    "*/*",
		"Accept-Language":           "en-US,en;q=0.9",
		"Sec-Ch-Ua-Mobile":          "?0",
		"Sec-Ch-Ua-Platform":        `"Windows"`,
		"Sec-Fetch-Dest":            "document",
		"Sec-Fetch-Mode":            "navigate",
		"Sec-Fetch-Site":            "same-origin",
		"Sec-Fetch-User":            "?1",
		"Upgrade-Insecure-Requests": "1",
		"User-Agent":                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0",
	}

	for k, v := range headers {
		req.Header.Set(k, v)
	}
}

func versionToNumber(version string) int64 {
	if version == "" {
		return 0
	}
	parts := strings.Split(version, ".")
	if len(parts) > 4 {
		return -1
	}
	var result int64
	for i := 0; i < len(parts); i++ {
		num, err := strconv.Atoi(parts[i])
		if err != nil {
			return -1 // Ошибка конвертации версии
		}
		result += int64(num) << uint(8*(3-i))
	}
	return result
}

func getMimeType(headers http.Header) string {
	contentType := headers.Get("Content-Type")
	if contentType == "" {
		return ""
	}
	mediaType, _, _ := mime.ParseMediaType(contentType)
	return mediaType
}

func extractTitle(content string) string {
	re := regexp.MustCompile(`(?i)<title>(.*?)</title>`)
	matches := re.FindStringSubmatch(content)
	if len(matches) < 2 {
		return ""
	}
	return strings.TrimSpace(html.UnescapeString(matches[1]))
}

func urlJoin(baseUrl string, paths ...string) (string, error) {
	if baseUrl == "" {
		return "", fmt.Errorf("base URL cannot be empty")
	}
	base, err := url.Parse(baseUrl)
	if err != nil {
		return "", fmt.Errorf("invalid base URL: %v", err)
	}
	for _, p := range paths {
		if p == "" {
			continue
		}
		ref, err := url.Parse(p)
		if err != nil {
			return "", fmt.Errorf("invalid path: %v", err)
		}
		base = base.ResolveReference(ref)
	}
	return base.String(), nil
}

func ensureScheme(u string) string {
	if !strings.Contains(u, "://") {
		u = "https://" + u
	}
	return u
}

func readURLs(filePath string) ([]string, error) {
	file := os.Stdin
	if filePath != "-" {
		var err error
		file, err = os.Open(filePath)
		if err != nil {
			return nil, err
		}
		defer file.Close()
	}

	scanner := bufio.NewScanner(file)
	var urls []string
	for scanner.Scan() {
		var line = scanner.Text()
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		urls = append(urls, line)
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return urls, nil
}

func writeResults(filePath string, results <-chan Result) error {
	file := os.Stdout
	if filePath != "-" {
		var err error
		file, err = os.Create(filePath)
		if err != nil {
			return err
		}
		defer file.Close()
	}

	writer := bufio.NewWriter(file)
	defer writer.Flush()

	for result := range results {
		jsonResult, err := json.Marshal(result)
		if err != nil {
			return err
		}
		if _, err := fmt.Fprintln(writer, string(jsonResult)); err != nil {
			return err
		}
		writer.Flush()
	}

	return nil
}

func setupLogger(logLevel string) {
	log.SetFormatter(&logrus.TextFormatter{
		ForceColors:   true,
		FullTimestamp: true,
	})

	switch logLevel {
	case "debug":
		log.SetLevel(logrus.DebugLevel)
	case "warn", "warning":
		log.SetLevel(logrus.WarnLevel)
	case "err", "error":
		log.SetLevel(logrus.ErrorLevel)
	default:
		log.SetLevel(logrus.InfoLevel)
	}
}

type Config struct {
	InputFile          string
	OutputFile         string
	MaxConcurrent      int
	Timeout            time.Duration
	RequestTimeout     time.Duration
	Delay              time.Duration
	DNSServer          string
	DNSProto           string
	LogLevel           string
	VulnarbilitiesFile string
}

func parseFlags() Config {
	inputFile := flag.String("i", "-", "Input file with URLs")
	outputFile := flag.String("o", "-", "Output file for results ")
	maxConcurrent := flag.Int("c", 20, "Maximum concurrent HTTP requests")
	timeout := flag.Duration("t", 15*time.Second, "HTTP Client timeout")
	requestTimeout := flag.Duration("rt", 5*time.Second, "Timeout for a request")
	delay := flag.Duration("d", 50*time.Millisecond, "Delay between requests")
	dnsServer := flag.String("dns-server", "", "DNS Server, e.g. 8.8.8.8:53")
	dnsProto := flag.String("dns-proto", "udp", "DNS Protocol")
	logLevel := flag.String("log", "info", "Log level: debug, info, warn, error")
	VulnarbilitiesFile := flag.String("f", "", "Path to YAML/TOML file with vulnerable plugins")
	flag.Parse()

	return Config{
		InputFile:          *inputFile,
		OutputFile:         *outputFile,
		MaxConcurrent:      *maxConcurrent,
		Timeout:            *timeout,
		RequestTimeout:     *requestTimeout,
		Delay:              *delay,
		DNSServer:          *dnsServer,
		DNSProto:           *dnsProto,
		LogLevel:           *logLevel,
		VulnarbilitiesFile: *VulnarbilitiesFile,
	}
}

func main() {
	config := parseFlags()

	fetchConfig := FetchConfig{
		Timeout:        config.Timeout,
		RequestTimeout: config.RequestTimeout,
		Delay:          config.Delay,
		DNSServer:      config.DNSServer,
		DNSProto:       config.DNSProto,
	}

	var Vulnarbilities WPVulnerabilities
	if config.VulnarbilitiesFile != "" {
		var err error
		Vulnarbilities, err = loadVulnarbilitiesFromFile(config.VulnarbilitiesFile)
		if err != nil {
			log.Fatalf("☠️ Error loading vulnerabilities: %v", err)
		}
	} else {
		Vulnarbilities = wpVulnerabilities // Используем захардкоженные значения
	}

	log.Info("🚀 Starting...")

	// Создаем WPVulnScanner с использованием Functional Options
	scanner := NewWPVulnScanner(
		Vulnarbilities,
		WithMaxConcurrent(config.MaxConcurrent),
		WithLogLevel(config.LogLevel),
		WithFetchConfig(fetchConfig),
	)

	urls, err := readURLs(config.InputFile)
	if err != nil {
		log.Fatalf("☠️ Error reading URLs: %v", err)
	}

	results := make(chan Result)
	var resultsWg sync.WaitGroup
	resultsWg.Add(1)

	go func() {
		defer resultsWg.Done()
		if err := writeResults(config.OutputFile, results); err != nil {
			log.Fatalf("☠️ Error writing results: %v", err)
		}
	}()

	scanner.Scan(urls, results)
	resultsWg.Wait()

	log.Info("🎉 Finished!")
}
