//go:build passive

package proxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"veo/pkg/logger"

	xproxy "golang.org/x/net/proxy"
)

var normalErrSubstrings = []string{
	"read: connection reset by peer",
	"write: broken pipe",
	"i/o timeout",
	"net/http: TLS handshake timeout",
	"io: read/write on closed pipe",
	"connect: connection refused",
	"connect: connection reset by peer",
	"use of closed network connection",
	"http2: stream closed",
	"http2: server",
	"http2: stream reset",
	"context canceled",
	"operation was canceled",
}

func logErr(prefix string, err error) {
	if err == nil {
		return
	}
	msg := err.Error()

	for _, str := range normalErrSubstrings {
		if strings.Contains(msg, str) {
			logger.Debugf("%s %v", prefix, err)
			return
		}
	}

	logger.Errorf("%s %v", prefix, err)
}

func transfer(prefix string, server, client io.ReadWriteCloser) {
	done := make(chan struct{})
	defer close(done)

	errChan := make(chan error)
	go func() {
		_, err := io.Copy(server, client)
		logger.Debugf("%s client copy end %v", prefix, err)
		client.Close()
		select {
		case <-done:
			return
		case errChan <- err:
			return
		}
	}()
	go func() {
		_, err := io.Copy(client, server)
		logger.Debugf("%s server copy end %v", prefix, err)
		server.Close()

		if clientConn, ok := client.(*wrapClientConn); ok {
			if tcpConn, ok := clientConn.Conn.(*net.TCPConn); ok {
				err := tcpConn.CloseRead()
				logger.Debugf("%s clientConn.Conn.(*net.TCPConn).CloseRead() %v", prefix, err)
			}
		}

		select {
		case <-done:
			return
		case errChan <- err:
			return
		}
	}()

	for i := 0; i < 2; i++ {
		if err := <-errChan; err != nil {
			logErr(prefix, err)
			return
		}
	}
}

func httpError(w http.ResponseWriter, error string, code int) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Proxy-Authenticate", `Basic realm="proxy"`)
	w.WriteHeader(code)
	fmt.Fprintln(w, error)
}

func ReaderToBuffer(r io.Reader, limit int64) ([]byte, io.Reader, error) {
	buf := bytes.NewBuffer(make([]byte, 0))
	lr := io.LimitReader(r, limit)

	_, err := io.Copy(buf, lr)
	if err != nil {
		return nil, nil, err
	}

	if int64(buf.Len()) == limit {
		return nil, io.MultiReader(bytes.NewBuffer(buf.Bytes()), r), nil
	}

	return buf.Bytes(), nil, nil
}

func CanonicalAddr(url *url.URL) string {
	port := url.Port()
	if port == "" {
		port = getDefaultPort(url.Scheme)
	}
	return net.JoinHostPort(url.Hostname(), port)
}

func getDefaultPort(scheme string) string {
	switch scheme {
	case "http":
		return "80"
	case "https":
		return "443"
	case "socks5":
		return "1080"
	default:
		return ""
	}
}

func GetProxyConn(ctx context.Context, proxyURL *url.URL, address string, sslInsecure bool) (net.Conn, error) {
	if proxyURL.Scheme == "socks5" {
		proxyAuth := &xproxy.Auth{}
		if proxyURL.User != nil {
			user := proxyURL.User.Username()
			pass, _ := proxyURL.User.Password()
			proxyAuth.User = user
			proxyAuth.Password = pass
		}
		dialer, err := xproxy.SOCKS5("tcp", proxyURL.Host, proxyAuth, xproxy.Direct)
		if err != nil {
			return nil, err
		}
		dc := dialer.(interface {
			DialContext(ctx context.Context, network, addr string) (net.Conn, error)
		})
		conn, err := dc.DialContext(ctx, "tcp", address)
		if err != nil {
			if conn != nil {
				conn.Close()
			}
			return nil, err
		}
		return conn, nil
	}

	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", proxyURL.Host)
	if err != nil {
		return nil, err
	}

	if proxyURL.Scheme == "https" {
		tlsConfig := &tls.Config{
			ServerName:         proxyURL.Hostname(),
			InsecureSkipVerify: sslInsecure,
		}
		tlsConn := tls.Client(conn, tlsConfig)
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			conn.Close()
			return nil, err
		}
		conn = tlsConn
	}

	connectReq := &http.Request{
		Method: "CONNECT",
		URL:    &url.URL{Opaque: address},
		Host:   address,
		Header: http.Header{},
	}
	if proxyURL.User != nil {
		connectReq.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(proxyURL.User.String())))
	}

	connectCtx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()

	didReadResponse := make(chan struct{})
	var resp *http.Response

	go func() {
		defer close(didReadResponse)
		err = connectReq.Write(conn)
		if err != nil {
			return
		}
		br := bufio.NewReader(conn)
		resp, err = http.ReadResponse(br, connectReq)
	}()

	select {
	case <-connectCtx.Done():
		conn.Close()
		<-didReadResponse
		return nil, connectCtx.Err()
	case <-didReadResponse:
	}

	if err != nil {
		conn.Close()
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		_, text, ok := strings.Cut(resp.Status, " ")
		conn.Close()
		if !ok {
			return nil, errors.New("unknown status code")
		}
		return nil, errors.New(text)
	}

	return conn, nil
}

func extractHost(hostWithPort string) string {
	host, _, err := net.SplitHostPort(hostWithPort)
	if err != nil {
		return hostWithPort
	}
	return host
}

func isTLS(buf []byte) bool {
	if len(buf) < 3 {
		return false
	}
	return buf[0] == 0x16 && buf[1] == 0x03 && buf[2] <= 0x03
}

type wrapListener struct {
	net.Listener
	proxy *Proxy
}

func (l *wrapListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}

	proxy := l.proxy
	wc := newWrapClientConn(c, proxy)
	connCtx := newConnContext(wc, proxy)
	wc.connCtx = connCtx

	proxy.onClientConnected(connCtx.ClientConn)

	return wc, nil
}

type wrapClientConn struct {
	net.Conn
	r       *bufio.Reader
	proxy   *Proxy
	connCtx *ConnContext

	closeMu   sync.Mutex
	closed    bool
	closeErr  error
	closeChan chan struct{}
}

func newWrapClientConn(c net.Conn, proxy *Proxy) *wrapClientConn {
	return &wrapClientConn{
		Conn:      c,
		r:         bufio.NewReader(c),
		proxy:     proxy,
		closeChan: make(chan struct{}),
	}
}

func (c *wrapClientConn) Peek(n int) ([]byte, error) {
	return c.r.Peek(n)
}

func (c *wrapClientConn) Read(data []byte) (int, error) {
	return c.r.Read(data)
}

func (c *wrapClientConn) Close() error {
	c.closeMu.Lock()
	if c.closed {
		c.closeMu.Unlock()
		return c.closeErr
	}

	c.closed = true
	c.closeErr = c.Conn.Close()
	c.closeMu.Unlock()
	close(c.closeChan)

	c.proxy.onClientDisconnected(c.connCtx.ClientConn)

	if c.connCtx.ServerConn != nil && c.connCtx.ServerConn.Conn != nil {
		c.connCtx.ServerConn.Conn.Close()
	}

	return c.closeErr
}

type wrapServerConn struct {
	net.Conn
	proxy   *Proxy
	connCtx *ConnContext

	closeMu  sync.Mutex
	closed   bool
	closeErr error
}

func (c *wrapServerConn) Close() error {
	c.closeMu.Lock()
	if c.closed {
		c.closeMu.Unlock()
		return c.closeErr
	}

	c.closed = true
	c.closeErr = c.Conn.Close()
	c.closeMu.Unlock()

	c.proxy.onServerDisconnected(c.connCtx)

	if !c.connCtx.ClientConn.Tls {
		if clientConn, ok := c.connCtx.ClientConn.Conn.(*wrapClientConn); ok {
			if tcpConn, ok := clientConn.Conn.(*net.TCPConn); ok {
				tcpConn.CloseRead()
			}
		}
	} else if !c.connCtx.closeAfterResponse {
		c.connCtx.ClientConn.Conn.Close()
	}

	return c.closeErr
}
