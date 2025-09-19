package consumer

import (
	"github.com/ALEYI17/InfraSight_sentinel/internal/config"
	"github.com/segmentio/kafka-go"
)

type KafkaConsumer struct{
  kafkaReader *kafka.Reader
  brokers []string
  topic string
  groupid string
}

func NewKafkaConsumer(cfg config.ProgramsConfig) *KafkaConsumer{

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

  }
}
