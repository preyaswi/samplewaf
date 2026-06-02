package interfaces

import "samplewaf/internal/models"

type ElasticService interface {
	SendLogToElasticsearch(event models.WAFEvent) error
}