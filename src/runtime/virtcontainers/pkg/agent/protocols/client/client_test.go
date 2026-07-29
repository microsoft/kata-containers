package client

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	grpcStatus "google.golang.org/grpc/status"
)

func startHybridVSockTestServer(t *testing.T, replyAfterAttempt int, replyDelay time.Duration) (string, *atomic.Int32) {
	t.Helper()

	socketPath := filepath.Join(t.TempDir(), "hybrid-vsock.sock")
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}

	var attempts atomic.Int32
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}

			attempt := int(attempts.Add(1))
			reader := bufio.NewReader(conn)
			if _, err := reader.ReadString('\n'); err != nil {
				_ = conn.Close()
				continue
			}
			if replyAfterAttempt > 0 && attempt >= replyAfterAttempt {
				time.Sleep(replyDelay)
				_, _ = fmt.Fprint(conn, "OK 1024\n")
			}
			_, _ = io.Copy(io.Discard, reader)
			_ = conn.Close()
		}
	}()

	t.Cleanup(func() {
		_ = listener.Close()
		<-done
	})

	return "hvsock:" + socketPath + ":1024", &attempts
}

func TestHybridVSockDialerRetriesDroppedHandshake(t *testing.T) {
	socket, attempts := startHybridVSockTestServer(t, 2, 0)

	started := time.Now()
	conn, err := hybridVSockDialer(context.Background(), socket, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	if attempts.Load() < 2 {
		t.Fatalf("expected a retry after the dropped handshake, got %d attempt(s)", attempts.Load())
	}
	if elapsed := time.Since(started); elapsed >= time.Second {
		t.Fatalf("dropped handshake consumed the full dial timeout: %v", elapsed)
	}
}

func TestHybridVSockDialerExpandsHandshakeWindow(t *testing.T) {
	socket, attempts := startHybridVSockTestServer(t, 2, 40*time.Millisecond)

	conn, err := hybridVSockDialer(context.Background(), socket, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	if attempts.Load() < 2 {
		t.Fatalf("expected a longer retry after the initial handshake window, got %d attempt(s)", attempts.Load())
	}
}

func TestHybridVSockDialerHonorsOverallTimeout(t *testing.T) {
	socket, attempts := startHybridVSockTestServer(t, 0, 0)

	const timeout = 120 * time.Millisecond
	started := time.Now()
	conn, err := hybridVSockDialer(context.Background(), socket, timeout)
	if conn != nil {
		conn.Close()
		t.Fatal("expected dialing to fail")
	}
	if grpcStatus.Code(err) != codes.DeadlineExceeded {
		t.Fatalf("expected DeadlineExceeded, got %v", err)
	}
	if attempts.Load() < 2 {
		t.Fatalf("expected multiple attempts, got %d", attempts.Load())
	}
	if elapsed := time.Since(started); elapsed > 500*time.Millisecond {
		t.Fatalf("dial exceeded its overall timeout: %v", elapsed)
	}
}
