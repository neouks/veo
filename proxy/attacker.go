//go:build passive

package proxy

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"

	"veo/pkg/logger"

	"github.com/lqqyt2423/go-mitmproxy/cert"
	"golang.org/x/net/http2"
)

type attackerListener struct {
	connChan chan net.Conn
}

func (l *attackerListener) accept(conn net.Conn) {
	l.connChan <- conn
}

func (l *attackerListener) Accept() (net.Conn, error) {
	c := <-l.connChan
	return c, nil
}

func (l *attackerListener) Close() error   { return nil }
func (l *attackerListener) Addr() net.Addr { return nil }

type attackerConn struct {
	net.Conn
	connCtx *ConnContext
}

type attacker struct {
	proxy    *Proxy
	ca       cert.CA
	server   *http.Server
	h2Server *http2.Server
	client   *http.Client
	listener *attackerListener
}

func newAttacker(proxy *Proxy) (*attacker, error) {
	ca, err := cert.NewSelfSignCA("")
	if err != nil {
		return nil, err
	}

	a := &attacker{
		proxy: proxy,
		ca:    ca,
		client: newNoRedirectClient(&http.Transport{
			Proxy:              proxy.realUpstreamProxy(),
			ForceAttemptHTTP2:  true,
			DisableCompression: true,
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: proxy.Opts.SslInsecure,
			},
		}),
		listener: &attackerListener{
			connChan: make(chan net.Conn),
		},
	}

	a.server = &http.Server{
		Handler: a,
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			return context.WithValue(ctx, connContextKey, c.(*attackerConn).connCtx)
		},
	}

	a.h2Server = &http2.Server{
		MaxConcurrentStreams: 100,
		NewWriteScheduler:    func() http2.WriteScheduler { return http2.NewPriorityWriteScheduler(nil) },
	}

	return a, nil
}

func (a *attacker) start() error {
	return a.server.Serve(a.listener)
}

func (a *attacker) serveConn(clientTlsConn *tls.Conn, connCtx *ConnContext) {
	connCtx.ClientConn.NegotiatedProtocol = clientTlsConn.ConnectionState().NegotiatedProtocol

	if connCtx.ClientConn.NegotiatedProtocol == "h2" && connCtx.ServerConn != nil {
		connCtx.ServerConn.client = newNoRedirectClient(&http2.Transport{
			DialTLSContext: func(ctx context.Context, network, addr string, cfg *tls.Config) (net.Conn, error) {
				return connCtx.ServerConn.tlsConn, nil
			},
			DisableCompression: true,
		})

		ctx := context.WithValue(context.Background(), connContextKey, connCtx)
		ctx, cancel := context.WithCancel(ctx)
		go func() {
			<-connCtx.ClientConn.Conn.(*wrapClientConn).closeChan
			cancel()
		}()
		go func() {
			a.h2Server.ServeConn(clientTlsConn, &http2.ServeConnOpts{
				Context:    ctx,
				Handler:    a,
				BaseConfig: a.server,
			})
		}()
		return
	}

	a.listener.accept(&attackerConn{
		Conn:    clientTlsConn,
		connCtx: connCtx,
	})
}

func (a *attacker) ServeHTTP(res http.ResponseWriter, req *http.Request) {
	if req.URL.Scheme == "" {
		req.URL.Scheme = "https"
	}
	if req.URL.Host == "" {
		req.URL.Host = req.Host
	}
	a.attack(res, req)
}

func (a *attacker) initHttpDialFn(req *http.Request) {
	connCtx := req.Context().Value(connContextKey).(*ConnContext)
	connCtx.dialFn = func(ctx context.Context) error {
		addr := CanonicalAddr(req.URL)
		c, err := a.proxy.getUpstreamConn(ctx, req)
		if err != nil {
			return err
		}
		proxy := a.proxy
		cw := &wrapServerConn{
			Conn:    c,
			proxy:   proxy,
			connCtx: connCtx,
		}

		serverConn := newServerConn()
		serverConn.Conn = cw
		serverConn.Address = addr
		serverConn.client = newNoRedirectClient(&http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return cw, nil
			},
			ForceAttemptHTTP2:  false,
			DisableCompression: true,
		})

		connCtx.ServerConn = serverConn
		proxy.onServerConnected(connCtx)

		return nil
	}
}

func (a *attacker) serverTlsHandshake(ctx context.Context, connCtx *ConnContext) error {
	proxy := a.proxy
	clientHello := connCtx.ClientConn.clientHello
	serverConn := connCtx.ServerConn

	serverTlsConfig := &tls.Config{
		InsecureSkipVerify: proxy.Opts.SslInsecure,
		ServerName:         clientHello.ServerName,
		NextProtos:         clientHello.SupportedProtos,
		CipherSuites:       clientHello.CipherSuites,
	}
	if len(clientHello.SupportedVersions) > 0 {
		minVersion := clientHello.SupportedVersions[0]
		maxVersion := clientHello.SupportedVersions[0]
		for _, version := range clientHello.SupportedVersions {
			if version < minVersion {
				minVersion = version
			}
			if version > maxVersion {
				maxVersion = version
			}
		}
		serverTlsConfig.MinVersion = minVersion
		serverTlsConfig.MaxVersion = maxVersion
	}
	serverTlsConn := tls.Client(serverConn.Conn, serverTlsConfig)
	serverConn.tlsConn = serverTlsConn
	if err := serverTlsConn.HandshakeContext(ctx); err != nil {
		return err
	}
	serverTlsState := serverTlsConn.ConnectionState()
	serverConn.tlsState = &serverTlsState
	proxy.onTLSEstablishedServer(connCtx)

	serverConn.client = newNoRedirectClient(&http.Transport{
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return serverTlsConn, nil
		},
		ForceAttemptHTTP2:  true,
		DisableCompression: true,
	})

	return nil
}

func (a *attacker) initHttpsDialFn(req *http.Request) {
	connCtx := req.Context().Value(connContextKey).(*ConnContext)

	connCtx.dialFn = func(ctx context.Context) error {
		_, err := a.httpsDial(ctx, req)
		if err != nil {
			return err
		}
		if err := a.serverTlsHandshake(ctx, connCtx); err != nil {
			return err
		}
		return nil
	}
}

func (a *attacker) httpsDial(ctx context.Context, req *http.Request) (net.Conn, error) {
	proxy := a.proxy
	connCtx := req.Context().Value(connContextKey).(*ConnContext)

	plainConn, err := proxy.getUpstreamConn(ctx, req)
	if err != nil {
		return nil, err
	}

	serverConn := newServerConn()
	serverConn.Address = req.Host
	serverConn.Conn = &wrapServerConn{
		Conn:    plainConn,
		proxy:   proxy,
		connCtx: connCtx,
	}
	connCtx.ServerConn = serverConn
	connCtx.proxy.onServerConnected(connCtx)

	return serverConn.Conn, nil
}

func (a *attacker) httpsTlsDial(ctx context.Context, cconn net.Conn, conn net.Conn) {
	connCtx := cconn.(*wrapClientConn).connCtx
	prefix := fmt.Sprintf("[Proxy.attacker.httpsTlsDial host=%s]", connCtx.ClientConn.Conn.RemoteAddr().String())

	var clientHello *tls.ClientHelloInfo
	clientHelloChan := make(chan *tls.ClientHelloInfo)
	serverTlsStateChan := make(chan *tls.ConnectionState)
	errChan1 := make(chan error, 1)
	errChan2 := make(chan error, 1)
	clientHandshakeDoneChan := make(chan struct{})

	clientTlsConn := tls.Server(cconn, &tls.Config{
		SessionTicketsDisabled: true,
		GetConfigForClient: func(chi *tls.ClientHelloInfo) (*tls.Config, error) {
			clientHelloChan <- chi
			nextProtos := make([]string, 0)

			select {
			case err := <-errChan2:
				return nil, err
			case serverTlsState := <-serverTlsStateChan:
				if serverTlsState.NegotiatedProtocol != "" {
					nextProtos = append([]string{serverTlsState.NegotiatedProtocol}, nextProtos...)
				}
			}

			c, err := a.ca.GetCert(chi.ServerName)
			if err != nil {
				return nil, err
			}
			return &tls.Config{
				SessionTicketsDisabled: true,
				Certificates:           []tls.Certificate{*c},
				NextProtos:             nextProtos,
			}, nil
		},
	})
	go func() {
		if err := clientTlsConn.HandshakeContext(ctx); err != nil {
			errChan1 <- err
			return
		}
		close(clientHandshakeDoneChan)
	}()

	select {
	case err := <-errChan1:
		cconn.Close()
		conn.Close()
		logger.Debugf("%s 客户端TLS握手失败: %v", prefix, err)
		return
	case clientHello = <-clientHelloChan:
	}
	connCtx.ClientConn.clientHello = clientHello

	if err := a.serverTlsHandshake(ctx, connCtx); err != nil {
		cconn.Close()
		conn.Close()
		errChan2 <- err
		logger.Debugf("%s 服务器TLS握手失败: %v", prefix, err)
		return
	}
	serverTlsStateChan <- connCtx.ServerConn.tlsState

	select {
	case err := <-errChan1:
		cconn.Close()
		conn.Close()
		logger.Debugf("%s 客户端TLS握手完成等待失败: %v", prefix, err)
		return
	case <-clientHandshakeDoneChan:
	}

	a.serveConn(clientTlsConn, connCtx)
}

func (a *attacker) httpsLazyAttack(ctx context.Context, cconn net.Conn, req *http.Request) {
	connCtx := cconn.(*wrapClientConn).connCtx
	prefix := fmt.Sprintf("[Proxy.attacker.httpsLazyAttack host=%s]", connCtx.ClientConn.Conn.RemoteAddr().String())

	clientTlsConn := tls.Server(cconn, &tls.Config{
		SessionTicketsDisabled: true,
		GetConfigForClient: func(chi *tls.ClientHelloInfo) (*tls.Config, error) {
			connCtx.ClientConn.clientHello = chi
			c, err := a.ca.GetCert(chi.ServerName)
			if err != nil {
				return nil, err
			}
			return &tls.Config{
				SessionTicketsDisabled: true,
				Certificates:           []tls.Certificate{*c},
				NextProtos:             []string{"http/1.1"},
			}, nil
		},
	})
	if err := clientTlsConn.HandshakeContext(ctx); err != nil {
		cconn.Close()
		logger.Debugf("%s 延迟模式TLS握手失败: %v", prefix, err)
		return
	}

	a.initHttpsDialFn(req)
	a.serveConn(clientTlsConn, connCtx)
}

func (a *attacker) attack(res http.ResponseWriter, req *http.Request) {
	proxy := a.proxy

	prefix := fmt.Sprintf("[Proxy.attacker.attack method=%s url=%s]", req.Method, req.URL)

	reply := func(response *Response, body io.Reader) {
		if response.Header != nil {
			for key, value := range response.Header {
				for _, v := range value {
					res.Header().Add(key, v)
				}
			}
		}
		res.WriteHeader(response.StatusCode)

		if body != nil {
			_, err := io.Copy(res, body)
			if err != nil {
				logErr(prefix, err)
			}
		}
		if response.BodyReader != nil {
			_, err := io.Copy(res, response.BodyReader)
			if err != nil {
				logErr(prefix, err)
			}
		}
		if response.Body != nil && len(response.Body) > 0 {
			_, err := res.Write(response.Body)
			if err != nil {
				logErr(prefix, err)
			}
		}
	}

	defer func() {
		if err := recover(); err != nil {
			logger.Warnf("%s Recovered: %v", prefix, err)
		}
	}()

	f := newFlow()
	f.Request = newRequest(req)
	f.ConnContext = req.Context().Value(connContextKey).(*ConnContext)
	defer f.finish()

	f.ConnContext.FlowCount.Add(1)

	rawReqURLHost := f.Request.URL.Host
	rawReqURLScheme := f.Request.URL.Scheme

	if proxy.onRequestheadersUntilResponse(f) {
		reply(f.Response, nil)
		return
	}

	var reqBody io.Reader = req.Body
	if !f.Stream {
		reqBuf, r, err := ReaderToBuffer(req.Body, proxy.Opts.StreamLargeBodies)
		reqBody = r
		if err != nil {
			logger.Errorf("%s %v", prefix, err)
			res.WriteHeader(502)
			return
		}

		if reqBuf == nil {
			logger.Warnf("%s request body size >= %v", prefix, proxy.Opts.StreamLargeBodies)
			f.Stream = true
		} else {
			f.Request.Body = reqBuf

			if proxy.onRequestUntilResponse(f) {
				reply(f.Response, nil)
				return
			}
			reqBody = bytes.NewReader(f.Request.Body)
		}
	}

	reqBody = proxy.onStreamRequestModifier(f, reqBody)

	proxyReqCtx := context.WithValue(req.Context(), proxyReqCtxKey, req)
	proxyReq, err := http.NewRequestWithContext(proxyReqCtx, f.Request.Method, f.Request.URL.String(), reqBody)
	if err != nil {
		logger.Errorf("%s %v", prefix, err)
		res.WriteHeader(502)
		return
	}

	for key, value := range f.Request.Header {
		for _, v := range value {
			proxyReq.Header.Add(key, v)
		}
	}

	useSeparateClient := f.UseSeparateClient
	if !useSeparateClient && (rawReqURLHost != f.Request.URL.Host || rawReqURLScheme != f.Request.URL.Scheme) {
		useSeparateClient = true
	}

	var proxyRes *http.Response
	if useSeparateClient {
		proxyRes, err = a.client.Do(proxyReq)
	} else {
		if f.ConnContext.ServerConn == nil && f.ConnContext.dialFn != nil {
			if err := f.ConnContext.dialFn(req.Context()); err != nil {
				logger.Errorf("%s %v", prefix, err)
				if strings.Contains(err.Error(), "Proxy Authentication Required") {
					httpError(res, "", http.StatusProxyAuthRequired)
					return
				}
				res.WriteHeader(502)
				return
			}
		}
		proxyRes, err = f.ConnContext.ServerConn.client.Do(proxyReq)
	}
	if err != nil {
		if err == context.Canceled {
			return
		}
		logErr(prefix, err)
		res.WriteHeader(502)
		return
	}

	if proxyRes.Close {
		f.ConnContext.closeAfterResponse = true
	}

	defer proxyRes.Body.Close()

	f.Response = &Response{
		StatusCode: proxyRes.StatusCode,
		Header:     proxyRes.Header,
		close:      proxyRes.Close,
	}

	if proxy.onResponseheadersUntilBody(f) {
		reply(f.Response, nil)
		return
	}

	var resBody io.Reader = proxyRes.Body
	if !f.Stream {
		resBuf, r, err := ReaderToBuffer(proxyRes.Body, proxy.Opts.StreamLargeBodies)
		resBody = r
		if err != nil {
			logger.Errorf("%s %v", prefix, err)
			res.WriteHeader(502)
			return
		}
		if resBuf == nil {
			logger.Warnf("%s response body size >= %v", prefix, proxy.Opts.StreamLargeBodies)
			f.Stream = true
		} else {
			f.Response.Body = resBuf
			proxy.onResponse(f)
		}
	}
	resBody = proxy.onStreamResponseModifier(f, resBody)

	reply(f.Response, resBody)
}
