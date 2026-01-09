package tools

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"
)

// 스캔 설정 상수
const (
	PortTimeout         = 500 * time.Millisecond
	MaxConcurrentHosts  = 50
	MaxConcurrentPorts  = 100
)

// DefaultPorts 스캔할 기본 포트 목록
var DefaultPorts = []int{
	21,    // FTP
	22,    // SSH
	23,    // Telnet
	25,    // SMTP
	53,    // DNS
	80,    // HTTP
	110,   // POP3
	111,   // RPC
	135,   // MSRPC
	139,   // NetBIOS
	143,   // IMAP
	443,   // HTTPS
	445,   // SMB
	993,   // IMAPS
	995,   // POP3S
	1433,  // MSSQL
	3306,  // MySQL
	3389,  // RDP
	5432,  // PostgreSQL
	8080,  // HTTP-Alt
	8443,  // HTTPS-Alt
}

// ServiceNames 포트-서비스 이름 매핑
var ServiceNames = map[int]string{
	21:    "ftp",
	22:    "ssh",
	23:    "telnet",
	25:    "smtp",
	53:    "domain",
	80:    "http",
	110:   "pop3",
	111:   "rpcbind",
	135:   "msrpc",
	139:   "netbios-ssn",
	143:   "imap",
	443:   "https",
	445:   "microsoft-ds",
	993:   "imaps",
	995:   "pop3s",
	1433:  "ms-sql-s",
	3306:  "mysql",
	3389:  "ms-wbt-server",
	5432:  "postgresql",
	8080:  "http-proxy",
	8443:  "https-alt",
}

// ScanResult 단일 호스트 스캔 결과
type ScanResult struct {
	Host      string
	OpenPorts []PortResult
	Latency   time.Duration
}

// PortResult 포트 스캔 결과
type PortResult struct {
	Port     int
	Protocol string
	State    string
	Service  string
}

// GetServiceName 포트 번호에 해당하는 서비스 이름 반환
func GetServiceName(port int) string {
	if name, ok := ServiceNames[port]; ok {
		return name
	}
	return "unknown"
}

// ParseTarget 단일 IP 또는 CIDR 범위를 IP 목록으로 변환
func ParseTarget(target string) ([]net.IP, error) {
	// CIDR 표기법인지 확인
	if strings.Contains(target, "/") {
		return parseCIDR(target)
	}

	// 단일 IP
	ip := net.ParseIP(target)
	if ip == nil {
		// 호스트명일 수 있음 - DNS 조회 시도
		ips, err := net.LookupIP(target)
		if err != nil {
			return nil, fmt.Errorf("invalid target: %s", target)
		}
		// IPv4만 반환
		var ipv4s []net.IP
		for _, ip := range ips {
			if ip.To4() != nil {
				ipv4s = append(ipv4s, ip)
			}
		}
		if len(ipv4s) == 0 {
			return nil, fmt.Errorf("no IPv4 address found for: %s", target)
		}
		return ipv4s, nil
	}

	return []net.IP{ip}, nil
}

// parseCIDR CIDR 범위를 IP 목록으로 변환
func parseCIDR(cidr string) ([]net.IP, error) {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("invalid CIDR: %s", cidr)
	}

	var ips []net.IP
	for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); incIP(ip) {
		// 복사본 생성 (slice 참조 문제 방지)
		ipCopy := make(net.IP, len(ip))
		copy(ipCopy, ip)
		ips = append(ips, ipCopy)
	}

	// 네트워크 주소와 브로드캐스트 주소 제외
	if len(ips) > 2 {
		ips = ips[1 : len(ips)-1]
	}

	return ips, nil
}

// incIP IP 주소를 1 증가
func incIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

// ScanPort 단일 포트 TCP Connect 스캔
func ScanPort(ctx context.Context, host string, port int, timeout time.Duration) bool {
	address := fmt.Sprintf("%s:%d", host, port)

	dialer := &net.Dialer{
		Timeout: timeout,
	}

	conn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// ScanHost 단일 호스트의 모든 포트 스캔 (병렬)
func ScanHost(ctx context.Context, host string, ports []int, timeout time.Duration) ScanResult {
	result := ScanResult{
		Host:      host,
		OpenPorts: []PortResult{},
	}

	startTime := time.Now()

	var wg sync.WaitGroup
	var mu sync.Mutex
	sem := make(chan struct{}, MaxConcurrentPorts)

	for _, port := range ports {
		wg.Add(1)
		go func(p int) {
			defer wg.Done()

			select {
			case <-ctx.Done():
				return
			case sem <- struct{}{}:
				defer func() { <-sem }()
			}

			if ScanPort(ctx, host, p, timeout) {
				mu.Lock()
				result.OpenPorts = append(result.OpenPorts, PortResult{
					Port:     p,
					Protocol: "tcp",
					State:    "open",
					Service:  GetServiceName(p),
				})
				mu.Unlock()
			}
		}(port)
	}

	wg.Wait()
	result.Latency = time.Since(startTime)

	// 포트 번호로 정렬
	sort.Slice(result.OpenPorts, func(i, j int) bool {
		return result.OpenPorts[i].Port < result.OpenPorts[j].Port
	})

	return result
}

// ScanNetwork 네트워크 전체 스캔 (CIDR 지원)
func ScanNetwork(ctx context.Context, target string, ports []int, timeout time.Duration) ([]ScanResult, error) {
	hosts, err := ParseTarget(target)
	if err != nil {
		return nil, err
	}

	var results []ScanResult
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, MaxConcurrentHosts)

	for _, host := range hosts {
		wg.Add(1)
		go func(h net.IP) {
			defer wg.Done()

			select {
			case <-ctx.Done():
				return
			case sem <- struct{}{}:
				defer func() { <-sem }()
			}

			result := ScanHost(ctx, h.String(), ports, timeout)
			if len(result.OpenPorts) > 0 {
				mu.Lock()
				results = append(results, result)
				mu.Unlock()
			}
		}(host)
	}

	wg.Wait()

	// IP 주소로 정렬
	sort.Slice(results, func(i, j int) bool {
		return results[i].Host < results[j].Host
	})

	return results, nil
}

// FormatAsNmap 스캔 결과를 nmap 출력 형식으로 변환
func FormatAsNmap(results []ScanResult, scanDuration time.Duration) string {
	var sb strings.Builder

	// 헤더
	now := time.Now().UTC().Format("2006-01-02 15:04:05")
	sb.WriteString(fmt.Sprintf("Starting Nmap 7.80 ( https://nmap.org ) at %s UTC\n", now))

	hostsUp := len(results)

	// 각 호스트별 결과
	for _, result := range results {
		sb.WriteString(fmt.Sprintf("Nmap scan report for %s\n", result.Host))
		sb.WriteString(fmt.Sprintf("Host is up (%.4fs latency).\n", result.Latency.Seconds()))
		sb.WriteString("PORT     STATE SERVICE\n")

		for _, port := range result.OpenPorts {
			// nmap 형식: "22/tcp   open  ssh"
			portStr := fmt.Sprintf("%d/%s", port.Port, port.Protocol)
			sb.WriteString(fmt.Sprintf("%-8s open  %s\n", portStr, port.Service))
		}
		sb.WriteString("\n")
	}

	// 푸터
	totalHosts := hostsUp
	if totalHosts == 0 {
		totalHosts = 1
	}
	sb.WriteString(fmt.Sprintf("Nmap done: %d IP addresses (%d hosts up) scanned in %.2f seconds\n",
		totalHosts, hostsUp, scanDuration.Seconds()))

	return sb.String()
}

// ScanResultsToMap 스캔 결과를 map 형태로 변환 (TRT 전송용)
// 반환 형식: []map[string]interface{} - TRT ScanResultHost 형식과 호환
func ScanResultsToMap(results []ScanResult) []map[string]interface{} {
	var hosts []map[string]interface{}

	for _, result := range results {
		var ports []map[string]interface{}
		for _, port := range result.OpenPorts {
			ports = append(ports, map[string]interface{}{
				"port":     port.Port,
				"protocol": port.Protocol,
				"state":    port.State,
				"service":  port.Service,
			})
		}

		host := map[string]interface{}{
			"ip":    result.Host,
			"ports": ports,
		}

		// hostname이 IP와 다르면 추가
		if result.Host != "" {
			host["hostname"] = nil
		}

		hosts = append(hosts, host)
	}

	return hosts
}
