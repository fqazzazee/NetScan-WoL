package agent

import (
	"os"
	"strings"

	"github.com/fqazzazee/netscan-wol/internal/protocol"
)

// DetectPlatform works out where the agent is running.
//
// This is reported to the hub for display and grouping, and it also explains
// capability differences: an agent in a bridged Docker network sees a different
// broadcast domain from one on the host, and knowing which is which turns a
// confusing empty scan into an obvious misconfiguration.
func DetectPlatform() protocol.Platform {
	// Kubernetes injects service environment variables into every pod unless
	// they are explicitly disabled, and the service account directory is
	// present regardless.
	if os.Getenv("KUBERNETES_SERVICE_HOST") != "" {
		return protocol.PlatformKubernetes
	}
	if _, err := os.Stat("/var/run/secrets/kubernetes.io/serviceaccount"); err == nil {
		return protocol.PlatformKubernetes
	}

	// Podman writes /run/.containerenv; Docker writes /.dockerenv. Checking
	// Podman first matters because Podman also creates /.dockerenv in some
	// compatibility modes.
	if _, err := os.Stat("/run/.containerenv"); err == nil {
		return protocol.PlatformPodman
	}
	if _, err := os.Stat("/.dockerenv"); err == nil {
		return protocol.PlatformDocker
	}

	// LXC and LXD set container= in PID 1's environment. Reading it needs
	// permission we may not have, so a failure here is not conclusive.
	if data, err := os.ReadFile("/proc/1/environ"); err == nil {
		env := string(data)
		if strings.Contains(env, "container=lxc") || strings.Contains(env, "container=lxd") {
			return protocol.PlatformLXC
		}
	}
	// Proxmox LXC guests carry this marker even when /proc/1/environ is
	// unreadable.
	if _, err := os.Stat("/dev/lxd/sock"); err == nil {
		return protocol.PlatformLXC
	}
	if data, err := os.ReadFile("/proc/self/cgroup"); err == nil {
		cgroup := string(data)
		switch {
		case strings.Contains(cgroup, "/lxc/"):
			return protocol.PlatformLXC
		case strings.Contains(cgroup, "/docker/"):
			return protocol.PlatformDocker
		}
	}

	return protocol.PlatformHost
}
