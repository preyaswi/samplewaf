package adapters

import (
	"bytes"
	"context"
	"encoding/json"
	"samplewaf/internal/models"

	"github.com/elastic/go-elasticsearch/v8"
	"github.com/rs/zerolog"
)

type ElasticAdapter struct {
	Client *elasticsearch.Client
	Logger zerolog.Logger
}

func (es *ElasticAdapter) SendLogToElasticsearch(logentry models.WAFEvent) error {
	data, err := json.Marshal(logentry)
	if err != nil {
		es.Logger.Error().Err(err).Msg("JSON marshal error")
		return err
	} 

	res, err := es.Client.Index(
		"waf-logs",
		bytes.NewReader(data),
		es.Client.Index.WithContext(context.Background()),
	)

	if err != nil {
		es.Logger.Error().Err(err).Msg("Elasticsearch index error")
		return err
	}

	defer func() {
		if closeErr := res.Body.Close(); closeErr != nil {
			es.Logger.Error().Err(closeErr).Msg("Error closing response body")
		}
	}()

	es.Logger.Info().Msg("Log sent to Elasticsearch")

	return nil
}
