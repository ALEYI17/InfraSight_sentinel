package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/ALEYI17/InfraSight_sentinel/internal/config"
	"github.com/ALEYI17/InfraSight_sentinel/pkg/consumer"
	"github.com/ALEYI17/InfraSight_sentinel/pkg/logutil"
	"go.uber.org/zap"
)

func main(){

  logutil.InitLogger()
  logger := logutil.GetLogger()

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

  kc :=consumer.NewKafkaConsumer(*cfg)

  if err := kc.Consume(ctx); err !=nil{
    logger.Warn("ERROR WHILE CONSUMING KAFKA EVENTS", zap.Error(err))
  }
}
