package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"regexp"
	"strings"
	"time"

	elasticsearch "github.com/elastic/go-elasticsearch/v8"

	redis "github.com/redis/go-redis/v9"
)

type Rule struct {
	Name    string
	Pattern *regexp.Regexp
	Score   int
}

var rules = []Rule{
	{
		Name:    "SQL Injection",
		Pattern: regexp.MustCompile(`(?i)(union\s+select|or\s+1=1|drop\s+table)`),
		Score:   50,
	},
	{
		Name:    "XSS",
		Pattern: regexp.MustCompile(`(?i)(<script>|javascript:|onerror=)`),
		Score:   50,
	},
	{
		Name:    "Path Traversal",
		Pattern: regexp.MustCompile(`\.\./`),
		Score:   40,
	},
}

const blockThreshold = 50

const (
	rateLimitRequests = 20
	rateLimitWindow   = 60 * time.Second

	maxMaliciousRequests = 3
	blockDuration        = 1 * time.Minute
)

type WAFLog struct {
	Timestamp string   `json:"timestamp"`
	IP        string   `json:"ip"`
	Method    string   `json:"method"`
	Path      string   `json:"path"`
	Query     string   `json:"query"`
	Score     int      `json:"score"`
	Action    string   `json:"action"`
	Rules     []string `json:"rules"`
	UserAgent string   `json:"user_agent"`
}

var (
	es    *elasticsearch.Client
	rdb   *redis.Client
	proxy *httputil.ReverseProxy
)

func main() {

	ctx := context.Background()

	//elastic search
	cfg := elasticsearch.Config{
		Addresses: []string{
			"http://localhost:9200",
		},
	}

	var err error
	es, err = elasticsearch.NewClient(cfg)
	if err != nil {
		log.Fatalf("Error creating Elasticsearch client: %s", err)
	}

	rdb = redis.NewClient(&redis.Options{
		Addr: "localhost:6379",
	})

	_, err = rdb.Ping(ctx).Result()
	if err != nil {
		log.Fatalf("Redis connection error: %s", err)
	}

	fmt.Println("connected to redis")

	backendURL, err := url.Parse("http://localhost:8081")
	if err != nil {
		log.Fatal(err)
	}

	proxy = httputil.NewSingleHostReverseProxy(backendURL)

	http.HandleFunc("/", wafHandler)

	fmt.Println("WAF running on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func wafHandler(w http.ResponseWriter, r *http.Request) {

	ip := getIp(r)

	ctx := r.Context()

	//check temp block
	blocked, err := rdb.Exists(ctx, "blocked:"+ip).Result()
	if err == nil && blocked == 1 {

		http.Error(w, "403 Forbidden - IP Temporarily Blocked", http.StatusForbidden)
		log.Printf("Blocked IP tried access: %s", ip)
		return

	}

	//rate limit
	allowed := checkRateLimit(ctx, ip)

	if !allowed {
		http.Error(w,
			"429 Too Many Requests",
			http.StatusTooManyRequests,
		)

		log.Printf("Rate limit exceeded: %s", ip)
		return
	}

	score, matches := inspectRequest(r)

	action := "allow"

	if score >= blockThreshold {
		action = "block"

		//track attack count
		attackKey := "attackS:" + ip

		count, err := rdb.Incr(ctx, attackKey).Result()

		if err == nil {
			rdb.Expire(ctx, attackKey, 10*time.Minute)
			log.Printf("Attack count for %s = %d", ip, count)

			//temp block after multiple attacks
			if count >= maxMaliciousRequests {
				rdb.Set(ctx, "blocked:"+ip, "1", blockDuration)
				log.Printf("IP temporarily blocked: %s", ip)
			}
		}
	}

	log.Printf("Request: %s %s Score=%d",
		r.Method,
		r.URL.String(),
		score,
	)

	if len(matches) > 0 {
		log.Printf("Matched Rules: %v", matches)
	}

	logEntry := WAFLog{

		Timestamp: time.Now().Format(time.RFC3339),
		IP:        r.RemoteAddr,
		Method:    r.Method,
		Path:      r.URL.Path,
		Query:     r.URL.RawQuery,
		Score:     score,
		Action:    action,
		Rules:     matches,
		UserAgent: r.UserAgent(),
	}

	go sendLogToElasticsearch(logEntry)

	if action == "block" {

		http.Error(w,
			"403 Forbidden - Malicious Request Blocked",
			http.StatusForbidden,
		)

		log.Println("Blocked request")
		return
	}

	proxy.ServeHTTP(w, r)
}
func inspectRequest(r *http.Request) (int, []string) {

	var score int
	var matchedRules []string

	var requestData strings.Builder

	requestData.WriteString(r.URL.String())

	for _, values := range r.URL.Query() {
		for _, v := range values {
			requestData.WriteString(v)
		}
	}

	for _, values := range r.Header {
		for _, v := range values {
			requestData.WriteString(v)
		}
	}

	if r.Body != nil {

		bodyBytes, err := io.ReadAll(r.Body)
		if err == nil {

			requestData.Write(bodyBytes)

			r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
		}
	}

	normalized := normalize(requestData.String())

	for _, rule := range rules {

		if rule.Pattern.MatchString(normalized) {
			score += rule.Score
			matchedRules = append(matchedRules, rule.Name)
		}
	}

	return score, matchedRules
}

func normalize(input string) string {

	decoded, err := url.QueryUnescape(input)
	if err == nil {
		input = decoded
	}

	input = strings.ToLower(input)

	input = strings.TrimSpace(input)

	return input
}

func sendLogToElasticsearch(logentry WAFLog) {
	data, err := json.Marshal(logentry)
	if err != nil {
		log.Println("JSON marshal error:", err)
		return
	}

	res, err := es.Index(
		"waf-logs",
		bytes.NewReader(data),
		es.Index.WithContext(context.Background()),
	)

	if err != nil {
		log.Println("Elasticsearch index error:", err)
		return
	}

	defer res.Body.Close()

	log.Println("Log sent to Elasticsearch")

}

func getIp(r *http.Request) string {
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return ip
}

func checkRateLimitwithgo(ctx context.Context, ip string) bool {
	key := "rate_limit:" + ip

	count, err := rdb.Incr(ctx, key).Result()

	if err != nil {
		return true
	}

	if count == 1 {
		rdb.Expire(ctx, key, rateLimitWindow)
	}
	return count <= rateLimitRequests
}

func checkRateLimit(ctx context.Context, ip string) bool {
	key := "rate_limit:" + ip

	res, err := rdb.Do(
		ctx, "FCALL", "rate_limit", 1, key,
		rateLimitRequests, int(rateLimitWindow.Seconds())).Int()

	if err != nil {
		log.Println("Redis function error:", err)
		return true
	}

	return res == 1
}
