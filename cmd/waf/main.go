package main

import (
	"context"
	"fmt"
	"net/http"
	"samplewaf/internal/adapters"
	"samplewaf/internal/logger"
	"samplewaf/internal/middleware"
	"samplewaf/internal/models"
	"samplewaf/internal/proxy"
	"samplewaf/internal/waf"
	"samplewaf/internal/workers"

	"github.com/elastic/go-elasticsearch/v8"
	"github.com/redis/go-redis/v9"
)

func main() {

	appLogger := logger.New()

	//elastic search
	cfg := elasticsearch.Config{
		Addresses: []string{
			"http://localhost:9200",
		},
	}

	var err error
	es, err := elasticsearch.NewClient(cfg)
	if err != nil {
		appLogger.Error().Err(err).Msg("Error creating Elasticsearch client")
		appLogger.Fatal().Err(err).Msg("Failed to create Elasticsearch client")
	}

	elasticadapter := &adapters.ElasticAdapter{
		Client: es,
		Logger: appLogger,
	}

	ctx := context.Background()

	rdb := redis.NewClient(&redis.Options{
		Addr: "localhost:6379",
	})

	_, err = rdb.Ping(ctx).Result()
	if err != nil {
		appLogger.Error().Err(err).Msg("Redis connection error")
		appLogger.Fatal().Err(err).Msg("Failed to connect to Redis")
	}

	fmt.Println("connected to redis")

	redisAdapter := &adapters.RedisAdapter{
		Client: rdb,
		Logger: appLogger,
	}

	// backendURL, err := url.Parse("http://localhost:8081")
	// if err != nil {
	// 	log.Fatal(err)
	// }
	// fmt.Println("the backend url", backendURL.Host)

	logChan := make(
		chan models.WAFEvent,
		100,
	)

	proxy, err := proxy.New(
		"http://localhost:8081",
	)

	if err != nil {
		appLogger.Fatal().Err(err).Msg("Failed to create proxy")
	}

	handler := &waf.Handler{
		Redis:   redisAdapter,
		LogChan: logChan,
		// Elastic: elasticadapter,
		Proxy:  proxy,
		Logger: appLogger,
	}

	// http.HandleFunc("/", handler.WafHandler)
	mux := http.NewServeMux()

	mux.HandleFunc(
		"/",
		handler.WafHandler,
	)

	worker := &workers.ElasticWorker{
		Elastic: elasticadapter,
		LogChan: logChan,
		Logger:  appLogger,
	}

	wrapped := middleware.LoggingMiddleware(
		mux,
		appLogger,
	)

	for i := 0; i < 5; i++ {
		go worker.Start()
	}

	fmt.Println("WAF running on :8080")
	err = http.ListenAndServe(
		":8080",
		wrapped,
	)

	if err != nil {
		appLogger.Fatal().Err(err).Msg("Failed to start server")
	}

	// log.Fatal(http.ListenAndServe(":8080", nil))
}

//interface implementation
//mock test  as well
//linters
