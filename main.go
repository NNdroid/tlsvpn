package main

import (
	"context"
	"crypto/rand"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// ======================= 全局随机数池 =======================
const RandomPoolSize = 1024 * 1024

var (
	randomPool []byte
	log        *zap.SugaredLogger
)

func init() {
	randomPool = make([]byte, RandomPoolSize)
	_, err := rand.Read(randomPool)
	if err != nil {
		panic("Failed to initialize random pool: " + err.Error())
	}
}

func initLogger(level string) {
	config := zap.NewDevelopmentConfig()
	var l zapcore.Level
	if err := l.UnmarshalText([]byte(level)); err != nil {
		l = zap.InfoLevel
	}
	config.Level = zap.NewAtomicLevelAt(l)
	config.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	baseLogger, _ := config.Build()
	log = baseLogger.Sugar()
}

func main() {
	mode := flag.String("mode", "", "server or client")
	psk := flag.String("psk", "quic_secret", "Pre-shared key")
	tapName := flag.String("tap", "tap0", "Name of the TAP device")
	macAddr := flag.String("mac", "", "Specify MAC address for TAP device (Client/Server)")
	addr := flag.String("addr", "0.0.0.0:4000", "Server: listen address (e.g., :4000) | Client: target addresses (comma-separated, e.g., 1.1.1.1:4000,[::1]:4000)")
	logLevel := flag.String("loglevel", "info", "Log level (e.g. info, debug)")

	v4cidr := flag.String("v4cidr", "10.0.0.0/24", "IPv4 CIDR block (Server only)")
	v6cidr := flag.String("v6cidr", "fd00::/64", "IPv6 CIDR block (Server only)")
	certFile := flag.String("cert", "", "TLS Certificate file (Server only)")
	keyFile := flag.String("key", "", "TLS Key file (Server only)")

	reqV4 := flag.String("req-v4", "", "Requested IPv4 (Client only)")
	reqV6 := flag.String("req-v6", "", "Requested IPv6 (Client only)")
	sni := flag.String("sni", "www.cloudflare.com", "SNI for TLS (Client only)")
	insecure := flag.Bool("insecure", false, "Skip TLS verify (Client only)")
	certHash := flag.String("cert-sha256", "", "Verify server cert SHA256 (hex encoded) (Client only)")
	fwmark := flag.Int("fwmark", 0, "Enable policy routing with specified fwmark (Client only)")

	brutal := flag.Bool("brutal", false, "Enable TCP Brutal congestion control")
	brutalUp := flag.Uint64("brutal-up", 100, "Brutal upload rate limit in Mbps")
	brutalDown := flag.Uint64("brutal-down", 500, "Brutal download rate limit in Mbps")

	conns := flag.Int("conns", 1, "Number of concurrent TCP connections for Load Balancing")
	fec := flag.Bool("fec", false, "Enable Packet Duplication FEC over Multipath")
	webAddr := flag.String("web", "", "Start Web Dashboard on specified address (e.g. :8080)")
	encrypt := flag.Bool("encrypt", false, "Enable inner payload AES-CTR XOR encryption")

	flag.Parse()
	initLogger(*logLevel)
	defer log.Sync()

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	if *mode == "server" {
		startServer(ctx, *psk, *tapName, *macAddr, *addr, *v4cidr, *v6cidr, *certFile, *keyFile, *brutal, *brutalUp, *brutalDown, *webAddr, *encrypt)
	} else if *mode == "client" {
		if *fec && *conns < 2 {
			log.Warnf("FEC (Packet Duplication) is enabled but conns < 2. Falling back to single connection.")
		}
		startClient(ctx, *psk, *tapName, *macAddr, *addr, *reqV4, *reqV6, *sni, *insecure, *certHash, *fwmark, *brutal, *brutalUp, *brutalDown, *conns, *fec, *encrypt)
	} else {
		fmt.Println("Usage: go run main.go -mode server|client [flags...]")
		os.Exit(1)
	}

	log.Info("Program exited gracefully.")
}
