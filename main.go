package main

import (
	"bufio"
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
	"strconv"
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

// filterList is a flag that accepts comma-separated values.
type filterList []string

func (f *filterList) String() string { return strings.Join(*f, ",") }
func (f *filterList) Set(v string) error {
	for _, s := range strings.Split(v, ",") {
		s = strings.TrimSpace(s)
		if s != "" {
			*f = append(*f, s)
		}
	}
	return nil
}

var (
	httpRequests = prometheus.NewCounterVec(
		prometheus.CounterOpts{Name: "ebpf_http_requests_total"},
		[]string{"pid", "comm", "method", "host", "path", "protocol"},
	)
	httpResponses = prometheus.NewCounterVec(
		prometheus.CounterOpts{Name: "ebpf_http_responses_total"},
		[]string{"pid", "comm", "status", "host", "protocol"},
	)
)

func init() {
	prometheus.MustRegister(httpRequests)
	prometheus.MustRegister(httpResponses)
}

// readHostPID reads the outermost PID from /proc/self/status (NSpid field).
func readHostPID() (uint32, error) {
	f, err := os.Open("/proc/self/status")
	if err != nil {
		return 0, err
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "NSpid:") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			break
		}
		pid, err := strconv.ParseUint(fields[1], 10, 32)
		if err != nil {
			return 0, fmt.Errorf("parsing NSpid: %w", err)
		}
		return uint32(pid), nil
	}
	return 0, fmt.Errorf("NSpid not found in /proc/self/status")
}

// parseEvent extracts method, path, host and status from raw HTTP/1.x payload.
// Returns empty strings if the payload is not HTTP/1.x (e.g. HTTP/2 binary frames).
func parseEvent(payload string) (method, path, host, status string, ok bool) {
	// Skip HTTP/2 connection preface — binary protocol, not parseable as HTTP/1.x
	if strings.HasPrefix(payload, "PRI * HTTP/2") {
		return "", "", "", "", false
	}
	// Skip HTTP/2 binary frames (start with a non-ASCII byte or known frame types)
	if len(payload) > 0 && payload[0] < 0x20 && payload[0] != '\r' && payload[0] != '\n' {
		return "", "", "", "", false
	}

	lines := strings.Split(payload, "\r\n")
	if len(lines) == 0 {
		return "", "", "", "", false
	}

	parts := strings.Fields(lines[0])

	if len(parts) >= 3 && strings.HasPrefix(parts[2], "HTTP/1") {
		// HTTP/1.x request: METHOD /path HTTP/1.x
		method = parts[0]
		path = parts[1]
	} else if len(parts) >= 2 && strings.HasPrefix(parts[0], "HTTP/1") {
		// HTTP/1.x response: HTTP/1.x STATUS reason
		method = "RES"
		status = parts[1]
	} else {
		return "", "", "", "", false
	}

	// Parse Host header
	for _, line := range lines[1:] {
		if line == "" {
			break
		}
		lower := strings.ToLower(line)
		if strings.HasPrefix(lower, "host:") {
			host = strings.TrimSpace(line[5:])
		}
	}

	return method, path, host, status, true
}

func pushToLoki(lokiURL string, pid uint32, comm, method, host, path, status, protocol string) {
	ts := time.Now().UnixNano()
	var line string
	if method == "RES" {
		line = fmt.Sprintf("method=RES status=%s host=%s protocol=%s", status, host, protocol)
	} else {
		line = fmt.Sprintf("method=%s host=%s path=%s protocol=%s", method, host, path, protocol)
	}

	payload := map[string]interface{}{
		"streams": []map[string]interface{}{{
			"stream": map[string]string{
				"job":      "ebpf-monitor",
				"pid":      fmt.Sprint(pid),
				"comm":     comm,
				"protocol": protocol,
				"host":     host,
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
	libPath     := flag.String("lib",     "/lib/x86_64-linux-gnu/libssl.so.3", "Path to libssl.so on the host")
	metricsAddr := flag.String("metrics", ":9091",                              "Prometheus metrics address")
	lokiURL     := flag.String("loki",    "http://127.0.0.1:3100/loki/api/v1/push", "Loki push URL")
	debug       := flag.Bool("debug",    false,                                 "Log raw payloads for debugging")

	var excludeComms filterList
	flag.Var(&excludeComms, "exclude", "Comma-separated comm names to exclude")
	flag.Parse()

	if len(excludeComms) == 0 {
		excludeComms = filterList{"monitor", "loki", "prometheus", "grafana", "lifecycle-serve"}
	}
	excludeSet := make(map[string]struct{}, len(excludeComms))
	for _, c := range excludeComms {
		excludeSet[c] = struct{}{}
	}
	log.Printf("excluding comms: %v", excludeComms)

	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading BPF objects: %v", err)
	}
	defer objs.Close()

	hostPID, err := readHostPID()
	if err != nil {
		log.Fatalf("reading host pid: %v", err)
	}
	key := uint32(0)
	if err := objs.SelfPid.Put(key, hostPID); err != nil {
		log.Fatalf("writing self pid to BPF map: %v", err)
	}
	log.Printf("self-filtering host pid %d", hostPID)

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
		if _, skip := excludeSet[comm]; skip {
			continue
		}

		payload := string(event.Payload[:event.Len])
		protocol := "HTTPS"
		if event.IsPlain == 1 {
			protocol = "HTTP"
		}

		if *debug {
			log.Printf("[DEBUG] %s pid=%d comm=%s payload=%q",
				protocol, event.PID, comm, payload[:min(len(payload), 120)])
		}

		method, path, host, status, ok := parseEvent(payload)
		if !ok {
			continue
		}

		switch method {
		case "RES":
			log.Printf("[%s] RES %s host=%s (pid=%d comm=%s)", protocol, status, host, event.PID, comm)
			httpResponses.WithLabelValues(fmt.Sprint(event.PID), comm, status, host, protocol).Inc()
			pushToLoki(*lokiURL, event.PID, comm, "RES", host, "-", status, protocol)
		default:
			fullURL := host + path
			log.Printf("[%s] REQ %s %s (pid=%d comm=%s)", protocol, method, fullURL, event.PID, comm)
			httpRequests.WithLabelValues(fmt.Sprint(event.PID), comm, method, host, path, protocol).Inc()
			pushToLoki(*lokiURL, event.PID, comm, method, host, path, status, protocol)
		}
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}