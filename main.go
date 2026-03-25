package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 -cflags "-D__TARGET_ARCH_x86 -I." bpf monitor.c

// HTTPEvent mirrors the C struct layout exactly.
type HTTPEvent struct {
	PID        uint32
	Comm       [16]byte
	Payload    [256]byte
	Len        uint32
	IsResponse uint8
	IsPlain    uint8
	_          [2]byte // padding
}

var httpRequests = prometheus.NewCounterVec(
	prometheus.CounterOpts{Name: "ebpf_http_requests_total"},
	[]string{"pid", "comm", "method", "path", "protocol"},
)

func init() { prometheus.MustRegister(httpRequests) }

func pushToLoki(lokiURL string, pid uint32, comm, method, path, status, protocol string) {
	ts := time.Now().UnixNano()
	line := fmt.Sprintf("method=%s path=%s status=%s protocol=%s", method, path, status, protocol)
	payload := map[string]interface{}{
		"streams": []map[string]interface{}{{
			"stream": map[string]string{
				"job":      "ebpf-monitor",
				"pid":      fmt.Sprint(pid),
				"comm":     comm,
				"protocol": protocol,
			},
			"values": [][]string{{fmt.Sprint(ts), line}},
		}},
	}
	body, err := json.Marshal(payload)
	if err != nil {
		log.Printf("loki marshal: %v", err)
		return
	}
	resp, err := http.Post(lokiURL, "application/json", bytes.NewBuffer(body))
	if err != nil {
		log.Printf("loki push: %v", err)
		return
	}
	resp.Body.Close()
}

func main() {
	libPath := flag.String("lib", "/usr/lib/x86_64-linux-gnu/libssl.so.3", "Path to libssl.so on the host")
	metricsAddr := flag.String("metrics", ":9091", "Prometheus metrics address")
	lokiURL := flag.String("loki", "http://127.0.0.1:3100/loki/api/v1/push", "Loki push URL")
	flag.Parse()

	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading BPF objects: %v", err)
	}
	defer objs.Close()

	// ---- HTTPS uprobes ----
	ex, err := link.OpenExecutable(*libPath)
	if err != nil {
		log.Fatalf("opening library %s: %v", *libPath, err)
	}

	lWrite, err := ex.Uprobe("SSL_write", objs.ProbeSslWrite, nil)
	if err != nil {
		log.Fatalf("attaching SSL_write uprobe: %v", err)
	}
	defer lWrite.Close()

	lReadEntry, err := ex.Uprobe("SSL_read", objs.ProbeSslReadEntry, nil)
	if err != nil {
		log.Fatalf("attaching SSL_read uprobe: %v", err)
	}
	defer lReadEntry.Close()

	lReadRet, err := ex.Uretprobe("SSL_read", objs.ProbeSslReadReturn, nil)
	if err != nil {
		log.Fatalf("attaching SSL_read uretprobe: %v", err)
	}
	defer lReadRet.Close()

	// ---- Plain HTTP kprobes ----
	lTcpSend, err := link.Kprobe("tcp_sendmsg", objs.ProbeTcpSendmsg, nil)
	if err != nil {
		log.Fatalf("attaching tcp_sendmsg kprobe: %v", err)
	}
	defer lTcpSend.Close()

	lTcpRecv, err := link.Kprobe("tcp_recvmsg", objs.ProbeTcpRecvmsg, nil)
	if err != nil {
		log.Fatalf("attaching tcp_recvmsg kprobe: %v", err)
	}
	defer lTcpRecv.Close()

	lTcpRecvRet, err := link.Kretprobe("tcp_recvmsg", objs.ProbeTcpRecvmsgReturn, nil)
	if err != nil {
		log.Fatalf("attaching tcp_recvmsg kretprobe: %v", err)
	}
	defer lTcpRecvRet.Close()

	// ---- Ring buffer ----
	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		log.Fatalf("opening ringbuf reader: %v", err)
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sig
		log.Println("shutting down...")
		rd.Close()
	}()

	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())
	srv := &http.Server{Addr: *metricsAddr, Handler: mux}
	go func() {
		log.Printf("metrics at %s/metrics", *metricsAddr)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("metrics server: %v", err)
		}
	}()

	log.Printf("monitoring HTTP and HTTPS (lib: %s)", *libPath)

	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			log.Printf("ringbuf read: %v", err)
			continue
		}

		var event HTTPEvent
		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &event); err != nil {
			log.Printf("parsing event: %v", err)
			continue
		}

		comm := string(bytes.Trim(event.Comm[:], "\x00"))
		payload := string(event.Payload[:event.Len])
		protocol := "HTTPS"
		if event.IsPlain == 1 {
			protocol = "HTTP"
		}

		lines := strings.Split(payload, "\r\n")
		if len(lines) == 0 {
			continue
		}
		parts := strings.Fields(lines[0])

		switch {
		case event.IsResponse == 0 && len(parts) >= 3 && strings.HasPrefix(parts[2], "HTTP/"):
			log.Printf("[%s] REQ %s %s (pid=%d comm=%s)", protocol, parts[0], parts[1], event.PID, comm)
			httpRequests.WithLabelValues(fmt.Sprint(event.PID), comm, parts[0], parts[1], protocol).Inc()
			pushToLoki(*lokiURL, event.PID, comm, parts[0], parts[1], "REQ", protocol)

		case event.IsResponse == 1 && len(parts) >= 2 && strings.HasPrefix(parts[0], "HTTP/"):
			log.Printf("[%s] RES %s (pid=%d comm=%s)", protocol, parts[1], event.PID, comm)
			pushToLoki(*lokiURL, event.PID, comm, "RES", "-", parts[1], protocol)
		}
	}
}
