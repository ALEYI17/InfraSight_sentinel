package connect

import (
	"fmt"
	"net"
	"strings"

	"github.com/ALEYI17/InfraSight_sentinel/internal/grpc/pb"
	"github.com/ALEYI17/InfraSight_sentinel/internal/programs"
)

type KubernetesAPIConnection struct{}

func (r *KubernetesAPIConnection) Name() string { return "KubernetesAPIConnection" }

func isPrivateIPv4(addr string) bool {
	ip := net.ParseIP(addr)
	if ip == nil {
		return false
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return false
	}
	b0 := ip4[0]
	b1 := ip4[1]
	if b0 == 10 {
		return true
	}
	if b0 == 192 && b1 == 168 {
		return true
	}
	if b0 == 172 && b1 >= 16 && b1 <= 31 {
		return true
	}
	return false
}

func (r *KubernetesAPIConnection) Evaluate(ev *pb.EbpfEvent) (bool, string) {
	// Only consider container-originated events
	if !programs.IsContainerEvent(ev) {
		return false, ""
	}

	netEv, ok := ev.Payload.(*pb.EbpfEvent_Network)
	if !ok || netEv.Network == nil {
		return false, ""
	}

	daddr := strings.TrimSpace(netEv.Network.Daddrv4)
	dport := strings.TrimSpace(netEv.Network.Dport)

	// K8s API is commonly on 443 or 6443. If the destination is a private IP
	// (cluster-internal) and the port matches, flag it.
	if (dport == "443" || dport == "6443") && isPrivateIPv4(daddr) {
		msg := fmt.Sprintf(
			"Container process %s (pid=%d, image=%s) connected to K8s API %s:%s",
			ev.Comm, ev.Pid, ev.ContainerImage, daddr, dport,
		)
		return true, msg
	}

	// Optionally: flag connections to cluster API domain names if resolved_domain is present
	if netEv.Network.ResolvedDomain != "" {
		domain := strings.ToLower(netEv.Network.ResolvedDomain)
		if strings.Contains(domain, "kubernetes") || strings.Contains(domain, "k8s") {
			msg := fmt.Sprintf(
				"Container process %s (pid=%d, image=%s) connected to domain %s",
				ev.Comm, ev.Pid, ev.ContainerImage, netEv.Network.ResolvedDomain,
			)
			return true, msg
		}
	}

	return false, ""
}
