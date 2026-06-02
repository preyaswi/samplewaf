package workers

import (
	"samplewaf/internal/interfaces"
	"samplewaf/internal/models"
	"time"

	"github.com/rs/zerolog"
)

type ElasticWorker struct {
	Elastic interfaces.ElasticService
	LogChan chan models.WAFEvent
	Logger  zerolog.Logger
}

func (w *ElasticWorker) Start() {

	for logEntry := range w.LogChan {

		var err error

		for i := 0; i < 3; i++ {

			err = w.Elastic.SendLogToElasticsearch(logEntry)

			if err == nil {
				break
			}

			time.Sleep(time.Second)
		}

		if err != nil {
			w.Logger.Error().
				Err(err).
				Msg("failed to send log to elasticsearch")
		}
	}
}
