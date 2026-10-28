// Reference benchmark only. See README: this uses a different Chromium version.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/miekg/dns"
	cronet "github.com/sagernet/cronet-go"
	_ "github.com/sagernet/cronet-go/lib/darwin_arm64"
	M "github.com/sagernet/sing/common/metadata"
)

func must(err error) {
	if err != nil {
		panic(err)
	}
}
func writeAll(conn net.Conn, data []byte) {
	for len(data) > 0 {
		n, err := conn.Write(data)
		must(err)
		if n == 0 {
			panic(io.ErrShortWrite)
		}
		data = data[n:]
	}
}
func usage() (float64, uint64) {
	var r syscall.Rusage
	must(syscall.Getrusage(syscall.RUSAGE_SELF, &r))
	scale := uint64(1024)
	if runtime.GOOS == "darwin" {
		scale = 1
	}
	return float64(r.Utime.Sec+r.Stime.Sec) + float64(r.Utime.Usec+r.Stime.Usec)/1e6, uint64(r.Maxrss) * scale
}
func rss() uint64 {
	data, err := exec.Command("ps", "-o", "rss=", "-p", strconv.Itoa(os.Getpid())).Output()
	must(err)
	n, err := strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
	must(err)
	return n * 1024
}
func quantile(v []float64, q float64) float64 {
	sort.Float64s(v)
	return v[int(float64(len(v)-1)*q+0.5)]
}
func newClient() *cronet.NaiveClient {
	server, err := url.Parse(os.Getenv("NAIVE_BENCH_PROXY"))
	must(err)
	ca, err := os.ReadFile(os.Getenv("NAIVE_BENCH_CA"))
	must(err)
	port, err := strconv.ParseUint(server.Port(), 10, 16)
	must(err)
	password, _ := server.User.Password()
	config := cronet.NaiveClientOptions{Context: context.Background(), ServerAddress: M.ParseSocksaddrHostPort("127.0.0.1", uint16(port)),
		ServerName: server.Hostname(), Username: server.User.Username(), Password: password, QUIC: server.Scheme == "quic", TrustedRootCertificates: string(ca),
		DNSResolver: func(_ context.Context, q *dns.Msg) *dns.Msg {
			r := new(dns.Msg)
			r.SetReply(q)
			if len(q.Question) > 0 && q.Question[0].Qtype == dns.TypeA {
				r.Answer = append(r.Answer, &dns.A{Hdr: dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.IPv4(127, 0, 0, 1)})
			}
			return r
		}}
	client, err := cronet.NewNaiveClient(config)
	must(err)
	must(client.Start())
	return client
}
func main() {
	mode := flag.String("mode", "bulk", "")
	connections := flag.Int("connections", 1, "")
	clientsCount := flag.Int("clients", 1, "")
	block := flag.Int("block", 65536, "")
	total := flag.Int("bytes", 134217728, "")
	iterations := flag.Int("iterations", 500, "")
	parallel := flag.Int("parallel", 1, "")
	_ = flag.Int("io-workers", 1, "ignored; Cronet allocates a network thread per engine")
	flag.Parse()
	runtime.GOMAXPROCS(4)
	origin, err := strconv.ParseUint(os.Getenv("NAIVE_BENCH_ORIGIN_PORT"), 10, 16)
	must(err)
	begin := time.Now()
	clients := make([]*cronet.NaiveClient, *clientsCount)
	for i := range clients {
		clients[i] = newClient()
	}
	if path := os.Getenv("NAIVE_BENCH_NETLOG"); path != "" {
		clients[0].Engine().StartNetLogToFile(path, false)
	}
	cold := time.Since(begin).Seconds() * 1000
	conns := make([]net.Conn, *connections)
	connectMS := make([]float64, *connections)
	var wg sync.WaitGroup
	for i := range conns {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			begin := time.Now()
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			c, err := clients[i%len(clients)].DialContext(ctx, "tcp", M.ParseSocksaddrHostPort("127.0.0.1", uint16(origin)))
			if err != nil && os.Getenv("NAIVE_BENCH_NETLOG") != "" {
				clients[0].Engine().StopNetLog()
			}
			must(err)
			connectMS[i] = time.Since(begin).Seconds() * 1000
			conns[i] = c
			data := bytes.Repeat([]byte{0x5a}, 256)
			receive := make([]byte, 256)
			for range 10 {
				writeAll(c, data)
				_, err = io.ReadFull(c, receive)
				must(err)
				if !bytes.Equal(data, receive) {
					panic("corrupt warmup")
				}
			}
		}(i)
	}
	wg.Wait()
	readyRSS := rss()
	cpuStart, _ := usage()
	start := time.Now()
	payload := 0
	var latencies []float64
	var lock sync.Mutex
	switch *mode {
	case "bulk", "small-writes":
		amount := *total / len(conns)
		payload = amount * len(conns)
		expected := bytes.Repeat([]byte{0x5a}, 65536)
		for _, c := range conns {
			wg.Add(1)
			go func(c net.Conn) {
				defer wg.Done()
				defer c.Close()
				done := make(chan struct{})
				go func() {
					defer close(done)
					data := bytes.Repeat([]byte{0x5a}, *block)
					for left := amount; left > 0; {
						n := min(left, len(data))
						writeAll(c, data[:n])
						left -= n
					}
				}()
				receive := make([]byte, 65536)
				for left := amount; left > 0; {
					n, err := c.Read(receive[:min(left, len(receive))])
					must(err)
					if n == 0 || !bytes.Equal(receive[:n], expected[:n]) {
						panic("corrupt transfer")
					}
					left -= n
				}
				<-done
			}(c)
		}
		wg.Wait()
	case "latency":
		payload = *iterations * *block * len(conns)
		for _, c := range conns {
			wg.Add(1)
			go func(c net.Conn) {
				defer wg.Done()
				defer c.Close()
				data := bytes.Repeat([]byte{0x5a}, *block)
				receive := make([]byte, *block)
				values := make([]float64, 0, *iterations)
				for range *iterations {
					begin := time.Now()
					writeAll(c, data)
					_, err := io.ReadFull(c, receive)
					must(err)
					if !bytes.Equal(receive, data) {
						panic("corrupt ping")
					}
					values = append(values, float64(time.Since(begin).Nanoseconds())/1e3)
				}
				lock.Lock()
				latencies = append(latencies, values...)
				lock.Unlock()
			}(c)
		}
		wg.Wait()
	case "idle":
		for _, c := range conns {
			wg.Add(1)
			go func(c net.Conn) { defer wg.Done(); defer c.Close(); var one [1]byte; _, _ = c.Read(one[:]) }(c)
		}
		time.Sleep(300 * time.Millisecond)
		resident := rss()
		cpu, peak := usage()
		result := map[string]any{"mode": *mode, "connections": *connections, "clients": *clientsCount, "rss_ready_bytes": readyRSS,
			"rss_blocked_bytes": resident, "peak_rss_bytes": peak, "cpu_seconds": cpu - cpuStart, "cold_init_ms": cold, "chromium": clients[0].Engine().Version()}
		for _, c := range conns {
			c.Close()
		}
		wg.Wait()
		for _, c := range clients {
			must(c.Close())
		}
		data, err := json.Marshal(result)
		must(err)
		fmt.Println(string(data))
		return
	case "churn", "churn-parallel":
		for _, c := range conns {
			c.Close()
		}
		count := 1
		if *mode == "churn-parallel" {
			count = *parallel
		}
		for range count {
			wg.Add(1)
			go func() {
				defer wg.Done()
				values := make([]float64, 0, *iterations/count)
				for range *iterations / count {
					begin := time.Now()
					c := newClient()
					must(c.Close())
					values = append(values, float64(time.Since(begin).Nanoseconds())/1e3)
				}
				lock.Lock()
				latencies = append(latencies, values...)
				lock.Unlock()
			}()
		}
		wg.Wait()
	default:
		panic("unsupported reference mode")
	}
	seconds := time.Since(start).Seconds()
	cpu, peak := usage()
	result := map[string]any{"mode": *mode, "connections": *connections, "clients": *clientsCount, "block": *block, "payload_bytes": payload,
		"seconds": seconds, "cpu_seconds": cpu - cpuStart, "payload_mib_per_second": float64(payload) / 1048576 / seconds,
		"cpu_ms_per_mib": (cpu - cpuStart) * 1000 / (float64(max(payload, 1)) / 1048576), "peak_rss_bytes": peak, "rss_ready_bytes": readyRSS,
		"cold_init_ms": cold, "connect_p50_ms": quantile(connectMS, .5), "connect_p99_ms": quantile(connectMS, .99), "chromium": clients[0].Engine().Version()}
	if len(latencies) > 0 {
		result["p50_us"] = quantile(latencies, .5)
		result["p95_us"] = quantile(latencies, .95)
		result["p99_us"] = quantile(latencies, .99)
	}
	for _, c := range clients {
		must(c.Close())
	}
	data, err := json.Marshal(result)
	must(err)
	fmt.Println(string(data))
}
