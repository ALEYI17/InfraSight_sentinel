package consumer

import (
	"context"

	"github.com/ALEYI17/InfraSight_sentinel/internal/config"
	"github.com/ALEYI17/InfraSight_sentinel/internal/grpc/pb"
	"github.com/ALEYI17/InfraSight_sentinel/pkg/engine"
	"github.com/ALEYI17/InfraSight_sentinel/pkg/logutil"
	"github.com/segmentio/kafka-go"
	"go.uber.org/zap"
	"google.golang.org/protobuf/proto"
)

type KafkaConsumer struct{
  kafkaReader *kafka.Reader
  brokers []string
  topic string
  groupid string
  engine *engine.Engine
}

func NewKafkaConsumer(cfg config.ProgramsConfig, e *engine.Engine) *KafkaConsumer{

  r := kafka.NewReader(kafka.ReaderConfig{
    Brokers: cfg.Kafka_broker,
    Topic: cfg.Kafka_topic,
    GroupID: cfg.Kafka_groupid,
  })

  return &KafkaConsumer{
    kafkaReader: r,
    brokers: cfg.Kafka_broker,
    topic: cfg.Kafka_topic,
    groupid: cfg.Kafka_groupid,
    engine: e,
  }
}

func(c *KafkaConsumer) Consume(ctx context.Context) error{
  defer c.kafkaReader.Close()
  logger := logutil.GetLogger()
  for{
    m,err := c.kafkaReader.ReadMessage(ctx)
    if err != nil {
      return err
    }

    var e pb.EbpfEvent

    err = proto.Unmarshal(m.Value,&e)
    if err != nil {
      logger.Error("failed to unmarshal event", zap.Error(err))
      continue
    }

    c.engine.HandleEvent(&e)
  }
}
