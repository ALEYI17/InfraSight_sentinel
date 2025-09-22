
# InfraSight Sentinel (Rules Engine)

This component of the **InfraSight** platform acts as the **rules engine** that evaluates eBPF events consumed from Kafka.
Its goal is to detect suspicious behaviors in real time, such as fileless execution, privilege escalation, or unusual system activity.

It is responsible for:

* Consuming events from **Kafka** produced by the InfraSight server.
* Applying security rules (based on syscalls and enriched process/container context).
* Generating **structured alerts** with detailed information about the process, container, and user involved.
* Integrating seamlessly with the rest of the **InfraSight** ecosystem.


## 📦 Features

* Modular rules engine: each rule implements a common interface (`Rule`).
* Supports multiple syscall event types (`execve`, `open`, `connect`, etc.).
* Enriched rule results include:

  * Rule name
  * Descriptive message
  * Process name and PID
  * User
  * Container ID and image
  * Flexible metadata via `map[string]string`
* Container-ready design (Docker/Kubernetes).
* High-throughput Kafka consumer for real-time detection.


## 🧱 Technologies Used and Dependencies

* [Go](https://golang.org/) (>= 1.21)
* [Kafka](https://kafka.apache.org/) for event ingestion
* [Uber Zap](https://github.com/uber-go/zap) for structured logging
* [Protocol Buffers](https://protobuf.dev/) for event definitions (`pb.EbpfEvent`)


## 🚀 Running with Docker

The official image is available on GitHub Container Registry:

```bash
docker run -it \
--network ebpf_server_default \
-e KAFKA_BROKER=broker:29092 \
-e KAFKA_TOPIC=ebpf_events \
-e KAFKA_GROUPID=rules-engine \
ghcr.io/aleyi17/infrasight-sentinel:latest
```


## ⚙️ Configuration

Configuration is managed via environment variables:

| Parameter      | Env Variable    | Default          | Description                            |
| -------------- | --------------- | ---------------- | -------------------------------------- |
| Kafka Broker   | `KAFKA_BROKER`  | `localhost:9092` | Kafka broker address                   |
| Kafka Topic    | `KAFKA_TOPIC`   | `ebpf_events`    | Kafka topic where events are published |
| Kafka Group ID | `KAFKA_GROUPID` | `rules-engine`   | Kafka consumer group ID                |


## 🛠️ Building from Source

### Clone the repository

```bash
git clone https://github.com/ALEYI17/infrasight-sentinel.git
cd infrasight-sentinel
```

### Build the binary

```bash
go build -o infrasight-sentinel ./cmd/main.go
```

### Run locally

```bash
KAFKA_BROKER=localhost:9092 \
KAFKA_TOPIC=ebpf_events \
KAFKA_GROUPID=rules-engine \
./infrasight-sentinel
```



## 📚 Related Repositories

This is part of the **[InfraSight](https://github.com/ALEYI17/InfraSight)** platform:

* [`infrasight-controller`](https://github.com/ALEYI17/infrasight-controller): Kubernetes controller to manage agents.
* [`ebpf_loader`](https://github.com/ALEYI17/ebpf_loader): Node-level agent that collects and sends eBPF telemetry.
* [`ebpf_server`](https://github.com/ALEYI17/ebpf_server): Receives and stores events (e.g., in ClickHouse).
* [`ebpf_deploy`](https://github.com/ALEYI17/ebpf_deploy): Helm charts to deploy the stack.
* [`InfraSight_ml`](https://github.com/ALEYI17/InfraSight_ml): Machine learning models for anomaly detection.
* [`InfraSight_sentinel`](https://github.com/ALEYI17/InfraSight_sentinel): Rules engine that generates alerts based on predefined detection logic.
