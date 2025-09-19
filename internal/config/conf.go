package config

import (
	"os"
	"strings"
)

type ProgramsConfig struct{
  Kafka_broker []string
  Kafka_topic string
  Kafka_groupid string
}

func LoadConfig () *ProgramsConfig{
  return &ProgramsConfig{
    Kafka_broker: getEnvAsSlice("KAFKA_BROKER", []string{"localhost:9092"}),
    Kafka_topic: getEnv("KAFKA_TOPIC", "ebpf_events"),
    Kafka_groupid: getEnv("KAFKA_GROUPID", "rules-engine"),
  }
}

func getEnv(key, fallback string) string {
    if value := os.Getenv(key); value != "" {
        return value
    }
    return fallback
}

func getEnvAsSlice(name string, defaultVal []string) []string {
    if valStr := os.Getenv(name); valStr != "" {
        parts := strings.Split(valStr, ",")
        for i := range parts {
            parts[i] = strings.TrimSpace(parts[i])
        }
        return parts
    }
    return defaultVal
}
