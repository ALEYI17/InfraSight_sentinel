package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/ALEYI17/InfraSight_sentinel/internal/config"
	"github.com/ALEYI17/InfraSight_sentinel/pkg/consumer"
	"github.com/ALEYI17/InfraSight_sentinel/pkg/logutil"
	"github.com/ALEYI17/InfraSight_sentinel/pkg/rules"
	"go.uber.org/zap"
)

func main(){

  logutil.InitLogger()
  logger := logutil.GetLogger()

  logger.Info("InfraSight Sentinel starting up...")

  ctx, cancel := context.WithCancel(context.Background())
  defer cancel()

  sigCh := make(chan os.Signal, 1)
  signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
  go func() {
    sig := <-sigCh
      logger.Info("Received termination signal, initiating graceful shutdown", zap.String("signal", sig.String()))
      cancel()
  }()

  cfg := config.LoadConfig()

  logger.Info("Configuration loaded", 
        zap.Strings("kafka_brokers", cfg.Kafka_broker),
        zap.String("kafka_topic", cfg.Kafka_topic),
  )

  rules.InitRules()

  kc :=consumer.NewKafkaConsumer(*cfg)

  logger.Info("Kafka consumer initialized", 
        zap.String("group_id", cfg.Kafka_groupid))


  if err := kc.Consume(ctx); err !=nil{
    logger.Warn("Error while consuming Kafka events", zap.Error(err))
  }

  logger.Info("InfraSight Sentinel has shut down")
}
