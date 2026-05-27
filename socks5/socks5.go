package socks5

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"slices"
	"strconv"

	"github.com/agnostic-t/neutrino-core/local"
)

var _ local.Proxy = (*Proxy)(nil)
var _ local.Request = (*Request)(nil)

type ProxyStatuses int

const (
	PROXY_UNREACHABLE_ERROR ProxyStatuses = iota
	PROXY_OK
	PROXY_GEN_FAILURE
)

type Proxy struct {
	bindAddr string
	listener net.Listener
}

func NewProxy(bindAddr string) *Proxy {
	return &Proxy{bindAddr: bindAddr}
}

func (p *Proxy) Listen() error {
	l, err := net.Listen("tcp", p.bindAddr)
	if err != nil {
		return err
	}
	p.listener = l
	return nil
}

func (p *Proxy) Accept() (local.Request, error) {
	conn, err := p.listener.Accept()
	if err != nil {
		return nil, err
	}

	if err := negotiate(conn); err != nil {
		return nil, fmt.Errorf("negotiation error: %s, %v", conn.RemoteAddr(), err)
	}

	target, err := parseRequest(conn)
	if err != nil {
		return nil, fmt.Errorf("request error: %s, %v", conn.RemoteAddr(), err)
	}

	return &Request{
		conn:   conn,
		target: target,
	}, nil
}

func (p *Proxy) Close() error {
	if p.listener != nil {
		return p.listener.Close()
	}
	return nil
}

// ==========================================

// Request implements local.Request
type Request struct {
	conn   net.Conn
	target string
}

func (r *Request) Target() string {
	return r.target
}

func (r *Request) Success(boundAddr string) (net.Conn, error) {
	if err := sendReply(r.conn, 0x00, "0.0.0.0:0"); err != nil {
		return nil, fmt.Errorf("reply error: %s, %w", r.conn.RemoteAddr(), err)
	}

	return r.conn, nil
}

func (r *Request) Fail(status int) {
	var replyCode byte

	s5_status := ProxyStatuses(status)
	switch s5_status {
	case PROXY_OK:
		replyCode = 0x00
	case PROXY_UNREACHABLE_ERROR:
		replyCode = 0x04 // Host unreachable
	case PROXY_GEN_FAILURE:
		replyCode = 0x01
	default:
		replyCode = 0x01 // General failure
	}

	if err := sendReply(r.conn, replyCode, "0.0.0.0:0"); err != nil {
		fmt.Fprintf(os.Stderr, "reply error: %s, %v", r.conn.RemoteAddr(), err)
	}

	r.conn.Close()
}

// ==============================

func negotiate(conn net.Conn) error {
	buf := make([]byte, 2)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return err
	}
	nmethods := int(buf[1])
	methods := make([]byte, nmethods)
	if _, err := io.ReadFull(conn, methods); err != nil {
		return err
	}

	hasNoAuth := slices.Contains(methods, 0x00)
	if !hasNoAuth {
		conn.Write([]byte{0x05, 0xFF}) // No acceptable methods
		return fmt.Errorf("no supported auth methods")
	}

	_, err := conn.Write([]byte{0x05, 0x00})
	return err
}

// reads target host
func parseRequest(conn net.Conn) (string, error) {
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return "", err
	}

	// If not CONNECT
	if header[0] != 0x05 {
		sendReply(conn, 0x05, "0.0.0.0:0")
		return "", fmt.Errorf("Wrong SOCKS version: %d", header[0])
	}
	if header[1] != 0x01 {
		sendReply(conn, 0x07, "0.0.0.0:0") // Command Not Supported
		return "", fmt.Errorf("Only CONNECT is supported")
	}

	atyp := header[3]
	var host string

	switch atyp {
	case 0x01: // IPv4
		ip := make([]byte, 4)
		if _, err := io.ReadFull(conn, ip); err != nil {
			return "", err
		}
		host = net.IP(ip).String()
	case 0x03: // Domain Name
		var domainLen byte
		if err := binary.Read(conn, binary.BigEndian, &domainLen); err != nil {
			return "", err
		}
		domain := make([]byte, domainLen)
		if _, err := io.ReadFull(conn, domain); err != nil {
			return "", err
		}
		host = string(domain)
	case 0x04: // IPv6
		ip := make([]byte, 16)
		if _, err := io.ReadFull(conn, ip); err != nil {
			return "", err
		}
		host = net.IP(ip).String()
	default:
		sendReply(conn, 0x08, "0.0.0.0:0") // Address Type Not Supported
		return "", fmt.Errorf("Unsupported addres type: %d", atyp)
	}

	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, portBuf); err != nil {
		return "", err
	}
	port := binary.BigEndian.Uint16(portBuf)

	return net.JoinHostPort(host, fmt.Sprintf("%d", port)), nil
}

func sendReply(conn net.Conn, reply byte, addr string) error {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return err
	}

	resp := []byte{0x05, reply, 0x00} // VER + REP + RSV

	if ip := net.ParseIP(host); ip != nil {
		if ipv4 := ip.To4(); ipv4 != nil {
			// IPv4: ATYP=0x01 + 4 bytes
			resp = append(resp, 0x01)
			resp = append(resp, ipv4...)
		} else {
			// IPv6: ATYP=0x04 + 16 bytes
			ipv6 := ip.To16()
			if ipv6 == nil {
				return fmt.Errorf("invalid IPv6 address")
			}
			resp = append(resp, 0x04)
			resp = append(resp, ipv6...)
		}
	} else {
		if len(host) > 255 {
			return fmt.Errorf("domain name too long")
		}
		resp = append(resp, 0x03, byte(len(host)))
		resp = append(resp, []byte(host)...)
	}

	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, uint16(port))
	resp = append(resp, portBytes...)

	_, err = conn.Write(resp)
	return err
}
