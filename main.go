package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpf -type http_event -cflags "-D__TARGET_ARCH_x86 -I." bpf monitor.c

type HTTPEvent struct {
	PID        uint32
	Comm       [16]byte
	Payload    [256]byte
	Len        uint32
	IsResponse uint8
	IsPlain    uint8
	_          [2]byte
}

var httpRequests = prometheus.NewCounterVec(
	prometheus.CounterOpts{Name: "ebpf_http_total"},
	[]string{"pid", "comm", "protocol", "direction"},
)

func init() { prometheus.MustRegister(httpRequests) }

// readHostPID extracts the PID from the host namespace to ensure filtering works correctly
func readHostPID() (uint32, error) {
	f, err := os.Open("/proc/self/status")
	if err != nil {
		return 0, err
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		if line := scanner.Text(); strings.HasPrefix(line, "NSpid:") {
			fields := strings.Fields(line)
			pid, _ := strconv.ParseUint(fields[1], 10, 32)
			return uint32(pid), nil
		}
	}
	return 0, fmt.Errorf("NSpid not found")
}

func main() {
	libPath := flag.String("lib", "/usr/lib/x86_64-linux-gnu/libssl.so.3", "Path to libssl")
	flag.Parse()

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

	// Update the Self-PID map to filter out this process's own traffic
	hostPID, _ := readHostPID()
	objs.SelfPid.Put(uint32(0), hostPID)
	log.Printf("Self-filtering host PID: %d", hostPID)

	// Attach Probes
	ex, _ := link.OpenExecutable(*libPath)
	upWrite, _ := ex.Uprobe("SSL_write", objs.ProbeSslWrite, nil)
	defer upWrite.Close()
	upRead, _ := ex.Uprobe("SSL_read", objs.ProbeSslReadEntry, nil)
	defer upRead.Close()
	upReadRet, _ := ex.Uretprobe("SSL_read", objs.ProbeSslReadReturn, nil)
	defer upReadRet.Close()

	kp, _ := link.Kprobe("tcp_sendmsg", objs.ProbeTcpSendmsg, nil)
	defer kp.Close()

	go http.ListenAndServe(":9091", promhttp.Handler())

	rd, _ := ringbuf.NewReader(objs.Events)
	log.Println("Monitoring started. Metrics at :9091/metrics")

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)

	for {
		record, err := rd.Read()
		if err != nil {
			continue
		}
		var event HTTPEvent
		binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &event)

		comm := string(bytes.Trim(event.Comm[:], "\x00"))
		payload := string(bytes.Trim(event.Payload[:event.Len], "\x00"))
		proto := "HTTPS"
		if event.IsPlain == 1 {
			proto = "HTTP"
		}
		dir := "REQ"
		if event.IsResponse == 1 {
			dir = "RES"
		}

		fmt.Printf("[%s][%s] PID: %d (%s) | Content: %s\n", proto, dir, event.PID, comm, payload)
		httpRequests.WithLabelValues(fmt.Sprint(event.PID), comm, proto, dir).Inc()
	}
}
