//go:build passive

package proxy

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/url"

	"veo/pkg/logger"
)

type Options struct {
	Addr              string
	StreamLargeBodies int64
	SslInsecure       bool
	Upstream          string
}

type Proxy struct {
	Opts   *Options
	Addons []Addon

	entry    *entry
	attacker *attacker
}

var proxyReqCtxKey = new(struct{})

func NewProxy(opts *Options) (*Proxy, error) {
	if opts.StreamLargeBodies <= 0 {
		opts.StreamLargeBodies = 1024 * 1024 * 5
	}

	proxy := &Proxy{
		Opts:   opts,
		Addons: make([]Addon, 0),
	}

	proxy.entry = newEntry(proxy)

	attacker, err := newAttacker(proxy)
	if err != nil {
		return nil, err
	}
	proxy.attacker = attacker

	return proxy, nil
}

func (proxy *Proxy) AddAddon(addon Addon) {
	proxy.Addons = append(proxy.Addons, addon)
}

func (proxy *Proxy) onClientConnected(client *ClientConn) {
	for _, addon := range proxy.Addons {
		addon.ClientConnected(client)
	}
}

func (proxy *Proxy) onClientDisconnected(client *ClientConn) {
	for _, addon := range proxy.Addons {
		addon.ClientDisconnected(client)
	}
}

func (proxy *Proxy) onServerConnected(connCtx *ConnContext) {
	for _, addon := range proxy.Addons {
		addon.ServerConnected(connCtx)
	}
}

func (proxy *Proxy) onServerDisconnected(connCtx *ConnContext) {
	for _, addon := range proxy.Addons {
		addon.ServerDisconnected(connCtx)
	}
}

func (proxy *Proxy) onTLSEstablishedServer(connCtx *ConnContext) {
	for _, addon := range proxy.Addons {
		addon.TlsEstablishedServer(connCtx)
	}
}

func (proxy *Proxy) onRequestheaders(flow *Flow) {
	for _, addon := range proxy.Addons {
		addon.Requestheaders(flow)
	}
}

func (proxy *Proxy) onRequestheadersUntilResponse(flow *Flow) bool {
	for _, addon := range proxy.Addons {
		addon.Requestheaders(flow)
		if flow.Response != nil {
			return true
		}
	}
	return false
}

func (proxy *Proxy) onRequestUntilResponse(flow *Flow) bool {
	for _, addon := range proxy.Addons {
		addon.Request(flow)
		if flow.Response != nil {
			return true
		}
	}
	return false
}

func (proxy *Proxy) onResponseheaders(flow *Flow) {
	for _, addon := range proxy.Addons {
		addon.Responseheaders(flow)
	}
}

func (proxy *Proxy) onResponseheadersUntilBody(flow *Flow) bool {
	for _, addon := range proxy.Addons {
		addon.Responseheaders(flow)
		if flow.Response != nil && flow.Response.Body != nil {
			return true
		}
	}
	return false
}

func (proxy *Proxy) onResponse(flow *Flow) {
	for _, addon := range proxy.Addons {
		addon.Response(flow)
	}
}

func (proxy *Proxy) onStreamRequestModifier(flow *Flow, in io.Reader) io.Reader {
	out := in
	for _, addon := range proxy.Addons {
		out = addon.StreamRequestModifier(flow, out)
	}
	return out
}

func (proxy *Proxy) onStreamResponseModifier(flow *Flow, in io.Reader) io.Reader {
	out := in
	for _, addon := range proxy.Addons {
		out = addon.StreamResponseModifier(flow, out)
	}
	return out
}

func newNoRedirectClient(transport http.RoundTripper) *http.Client {
	return &http.Client{
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func (proxy *Proxy) Start() error {
	go func() {
		if err := proxy.attacker.start(); err != nil {
			logger.Error(err)
		}
	}()
	return proxy.entry.start()
}

func (proxy *Proxy) Close() error {
	return proxy.entry.close()
}

func (proxy *Proxy) realUpstreamProxy() func(*http.Request) (*url.URL, error) {
	return func(cReq *http.Request) (*url.URL, error) {
		req := cReq.Context().Value(proxyReqCtxKey).(*http.Request)
		return proxy.getUpstreamProxyURL(req)
	}
}

func (proxy *Proxy) getUpstreamProxyURL(req *http.Request) (*url.URL, error) {
	if len(proxy.Opts.Upstream) > 0 {
		return url.Parse(proxy.Opts.Upstream)
	}
	cReq := &http.Request{URL: &url.URL{Scheme: "https", Host: req.Host}}
	return http.ProxyFromEnvironment(cReq)
}

func (proxy *Proxy) getUpstreamConn(ctx context.Context, req *http.Request) (net.Conn, error) {
	proxyURL, err := proxy.getUpstreamProxyURL(req)
	if err != nil {
		return nil, err
	}

	address := CanonicalAddr(req.URL)
	if proxyURL != nil {
		return GetProxyConn(ctx, proxyURL, address, proxy.Opts.SslInsecure)
	}
	return (&net.Dialer{}).DialContext(ctx, "tcp", address)
}

type Addon interface {
	ClientConnected(*ClientConn)
	ClientDisconnected(*ClientConn)
	ServerConnected(*ConnContext)
	ServerDisconnected(*ConnContext)
	TlsEstablishedServer(*ConnContext)
	Requestheaders(*Flow)
	Request(*Flow)
	Responseheaders(*Flow)
	Response(*Flow)
	StreamRequestModifier(*Flow, io.Reader) io.Reader
	StreamResponseModifier(*Flow, io.Reader) io.Reader
}

type BaseAddon struct{}

func (addon *BaseAddon) ClientConnected(*ClientConn)                            {}
func (addon *BaseAddon) ClientDisconnected(*ClientConn)                         {}
func (addon *BaseAddon) ServerConnected(*ConnContext)                           {}
func (addon *BaseAddon) ServerDisconnected(*ConnContext)                        {}
func (addon *BaseAddon) TlsEstablishedServer(*ConnContext)                      {}
func (addon *BaseAddon) Requestheaders(*Flow)                                   {}
func (addon *BaseAddon) Request(*Flow)                                          {}
func (addon *BaseAddon) Responseheaders(*Flow)                                  {}
func (addon *BaseAddon) Response(*Flow)                                         {}
func (addon *BaseAddon) StreamRequestModifier(f *Flow, in io.Reader) io.Reader  { return in }
func (addon *BaseAddon) StreamResponseModifier(f *Flow, in io.Reader) io.Reader { return in }
