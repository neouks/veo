//go:build passive

package proxy

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"

	"veo/internal/config"
	"veo/pkg/logger"
)

type entry struct {
	proxy  *Proxy
	server *http.Server
}

func newEntry(proxy *Proxy) *entry {
	e := &entry{proxy: proxy}
	e.server = &http.Server{
		Addr:    proxy.Opts.Addr,
		Handler: e,
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			return context.WithValue(ctx, connContextKey, c.(*wrapClientConn).connCtx)
		},
	}
	return e
}

func (e *entry) start() error {
	addr := e.server.Addr
	if addr == "" {
		addr = ":http"
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}

	logger.Infof("Listend at %v\n", e.server.Addr)
	pln := &wrapListener{
		Listener: ln,
		proxy:    e.proxy,
	}
	return e.server.Serve(pln)
}

func (e *entry) close() error {
	return e.server.Close()
}

func (e *entry) ServeHTTP(res http.ResponseWriter, req *http.Request) {
	proxy := e.proxy

	prefix := fmt.Sprintf("[Proxy.entry.ServeHTTP host=%s]", req.Host)

	if req.URL.IsAbs() && req.URL.Host != "" {
		host := extractHost(req.URL.Host)
		if !config.IsHostAllowed(host) {
			logger.Debugf("%s 主机被拒绝，拒绝代理: %s (原始: %s)", prefix, host, req.URL.Host)
			httpError(res, "Host not allowed", http.StatusForbidden)
			return
		}
	}

	if req.Method == "CONNECT" {
		e.handleConnect(res, req)
		return
	}

	proxy.attacker.initHttpDialFn(req)
	proxy.attacker.attack(res, req)
}

func (e *entry) handleConnect(res http.ResponseWriter, req *http.Request) {
	proxy := e.proxy

	prefix := fmt.Sprintf("[Proxy.entry.handleConnect host=%s]", req.Host)

	host := extractHost(req.Host)
	if !config.IsHostAllowed(host) {
		logger.Debugf("%s 主机被拒绝，拒绝CONNECT: %s (原始: %s)", prefix, host, req.Host)
		httpError(res, "Host not allowed", http.StatusForbidden)
		return
	}

	f := newFlow()
	f.Request = newRequest(req)
	f.ConnContext = req.Context().Value(connContextKey).(*ConnContext)
	f.ConnContext.Intercept = true
	defer f.finish()

	proxy.onRequestheaders(f)

	if f.ConnContext.ClientConn.UpstreamCert {
		e.httpsDialFirstAttack(res, req, f)
		return
	}

	e.httpsDialLazyAttack(res, req, f)
}

func (e *entry) establishConnection(res http.ResponseWriter, f *Flow) (net.Conn, error) {
	cconn, _, err := res.(http.Hijacker).Hijack()
	if err != nil {
		res.WriteHeader(502)
		return nil, err
	}
	_, err = io.WriteString(cconn, "HTTP/1.1 200 Connection Established\r\n\r\n")
	if err != nil {
		cconn.Close()
		return nil, err
	}

	f.Response = &Response{
		StatusCode: 200,
		Header:     make(http.Header),
	}

	e.proxy.onResponseheaders(f)

	return cconn, nil
}

func (e *entry) httpsDialFirstAttack(res http.ResponseWriter, req *http.Request, f *Flow) {
	proxy := e.proxy
	prefix := fmt.Sprintf("[Proxy.entry.httpsDialFirstAttack host=%s]", req.Host)

	conn, err := proxy.attacker.httpsDial(req.Context(), req)
	if err != nil {
		res.WriteHeader(502)
		return
	}

	cconn, err := e.establishConnection(res, f)
	if err != nil {
		conn.Close()
		return
	}

	peek, err := cconn.(*wrapClientConn).Peek(3)
	if err != nil {
		cconn.Close()
		conn.Close()
		return
	}
	if !isTLS(peek) {
		transfer(prefix, conn, cconn)
		cconn.Close()
		conn.Close()
		return
	}

	f.ConnContext.ClientConn.Tls = true
	proxy.attacker.httpsTlsDial(req.Context(), cconn, conn)
}

func (e *entry) httpsDialLazyAttack(res http.ResponseWriter, req *http.Request, f *Flow) {
	proxy := e.proxy
	prefix := fmt.Sprintf("[Proxy.entry.httpsDialLazyAttack host=%s]", req.Host)

	cconn, err := e.establishConnection(res, f)
	if err != nil {
		return
	}

	peek, err := cconn.(*wrapClientConn).Peek(3)
	if err != nil {
		cconn.Close()
		return
	}

	if !isTLS(peek) {
		conn, err := proxy.attacker.httpsDial(req.Context(), req)
		if err != nil {
			cconn.Close()
			return
		}
		transfer(prefix, conn, cconn)
		conn.Close()
		cconn.Close()
		return
	}

	f.ConnContext.ClientConn.Tls = true
	proxy.attacker.httpsLazyAttack(req.Context(), cconn, req)
}
