package socks5

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"slices"
	"strconv"
	"sync"

	"github.com/agnostic-t/neutrino-core/local"
)

var _ local.Proxy = (*Proxy)(nil)
var _ local.Request = (*Request)(nil)

type ProxyStatuses int
type RequestProto int

const (
	PROXY_UNREACHABLE_ERROR ProxyStatuses = iota
	PROXY_OK
	PROXY_GEN_FAILURE
)

const (
	REQUEST_UNKNOWN_PROTO RequestProto = iota
	REQUEST_TCP
	REQUEST_UDP
)

type Proxy struct {
	bindAddr string
	listener net.Listener

	reqChan  chan local.Request
	udpFlows map[string]net.Conn
	udpMutex sync.Mutex
}

func NewProxy(bindAddr string) *Proxy {
	return &Proxy{
		bindAddr: bindAddr,
		reqChan:  make(chan local.Request, 1024),
		udpFlows: make(map[string]net.Conn),
	}
}

func (p *Proxy) Listen() error {
	l, err := net.Listen("tcp", p.bindAddr)
	if err != nil {
		return err
	}
	p.listener = l

	go func() {
		for {
			conn, err := p.listener.Accept()
			if err != nil {
				return
			}

			go p.handleInitConn(conn)
		}
	}()

	return nil
}

func (p *Proxy) Accept() (local.Request, error) {
	req, ok := <-p.reqChan
	if !ok {
		return nil, io.EOF
	}
	return req, nil
}

func (p *Proxy) Close() error {
	if p.listener != nil {
		return p.listener.Close()
	}
	return nil
}

func (p *Proxy) handleInitConn(conn net.Conn) {
	if err := negotiate(conn); err != nil {
		// fmt.Errorf("negotiation error: %s, %v", conn.RemoteAddr(), err)
		return
	}

	target, err, reqProto := parseRequest(conn)
	if err != nil {
		// fmt.Errorf("request error: %s, %v", conn.RemoteAddr(), err)
		return
	}

	if reqProto == REQUEST_TCP {
		p.reqChan <- &Request{conn: conn, target: target, proto: "tcp"}
		return
	}

	if reqProto == REQUEST_UDP {
		udpAddr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
		udpConn, err := net.ListenUDP("udp", udpAddr)
		if err != nil {
			sendReply(conn, 0x01, "0.0.0.0:0")
			return
		}

		sendReply(conn, 0x00, udpConn.LocalAddr().String())

		go p.handleUDP(udpConn, conn)
	}
}

func (p *Proxy) handleUDP(udpConn *net.UDPConn, tcpControlConn net.Conn) {
	defer udpConn.Close()
	defer tcpControlConn.Close()

	buf := make([]byte, 65535)
	for {
		n, clientAddr, err := udpConn.ReadFromUDP(buf)
		if err != nil {
			return
		}

		target, payloadOffset, err := parseSocks5UDPHeader(buf[:n])
		if err != nil {
			continue
		}

		payload := buf[payloadOffset:n]
		flowKey := clientAddr.String() + "-" + target

		p.udpMutex.Lock()
		virtualConn, exists := p.udpFlows[flowKey]

		if !exists {
			left, right := net.Pipe()
			p.udpFlows[flowKey] = right
			virtualConn = right

			p.reqChan <- &Request{
				conn:   left,
				target: target,
				proto:  "udp",
			}

			go func() {
				defer right.Close()
				respBuf := make([]byte, 65535)
				for {
					rn, rerr := right.Read(respBuf)
					if rerr != nil {
						break
					}

					header := buildSocks5UDPHeader(target)
					udpConn.WriteToUDP(append(header, respBuf[:rn]...), clientAddr)
				}

				p.udpMutex.Lock()
				delete(p.udpFlows, flowKey)
				p.udpMutex.Unlock()
			}()
		}
		p.udpMutex.Unlock()

		virtualConn.Write(payload)
	}
}

func parseSocks5UDPHeader(buf []byte) (string, int, error) {
	// 2(RSV) + 1(FRAG) + 1(ATYP)
	if len(buf) < 4 {
		return "", 0, fmt.Errorf("packet too short")
	}

	// buf[0], buf[1] - RSV (0x00, 0x00)
	if buf[2] != 0x00 {
		return "", 0, fmt.Errorf("fragmentation not supported")
	}

	atyp := buf[3]
	var host string
	offset := 4

	switch atyp {
	case 0x01: // IPv4: 4 bytes
		if len(buf) < offset+4+2 {
			return "", 0, fmt.Errorf("packet too short for IPv4")
		}
		host = net.IP(buf[offset : offset+4]).String()
		offset += 4

	case 0x03: // Domain Name: 1 byte length + domain name
		if len(buf) < offset+1 {
			return "", 0, fmt.Errorf("packet too short for Domain")
		}
		domainLen := int(buf[offset])
		offset++
		if len(buf) < offset+domainLen+2 {
			return "", 0, fmt.Errorf("packet too short for Domain string")
		}
		host = string(buf[offset : offset+domainLen])
		offset += domainLen

	case 0x04: // IPv6: 16 bytes
		if len(buf) < offset+16+2 {
			return "", 0, fmt.Errorf("packet too short for IPv6")
		}
		host = net.IP(buf[offset : offset+16]).String()
		offset += 16

	default:
		return "", 0, fmt.Errorf("unsupported address type: %d", atyp)
	}

	port := binary.BigEndian.Uint16(buf[offset : offset+2])
	offset += 2

	target := net.JoinHostPort(host, strconv.Itoa(int(port)))

	return target, offset, nil
}

func buildSocks5UDPHeader(target string) []byte {
	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		return nil
	}

	portInt, _ := strconv.Atoi(portStr)

	// RSV (0x00, 0x00) + FRAG (0x00)
	header := []byte{0x00, 0x00, 0x00}

	if ip := net.ParseIP(host); ip != nil {
		if ipv4 := ip.To4(); ipv4 != nil {
			// IPv4: ATYP = 0x01
			header = append(header, 0x01)
			header = append(header, ipv4...)
		} else {
			// IPv6: ATYP = 0x04
			header = append(header, 0x04)
			header = append(header, ip.To16()...)
		}
	} else {
		// Domain: ATYP = 0x03
		header = append(header, 0x03, byte(len(host)))
		header = append(header, []byte(host)...)
	}

	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, uint16(portInt))
	header = append(header, portBytes...)

	return header
}

// ==========================================

// Request implements local.Request
type Request struct {
	conn   net.Conn
	target string
	proto  string
}

func (r *Request) Target() string {
	return r.target
}

func (r *Request) Proto() string {
	return r.proto
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
func parseRequest(conn net.Conn) (string, error, RequestProto) {
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return "", err, REQUEST_UNKNOWN_PROTO
	}

	// If not CONNECT
	if header[0] != 0x05 {
		sendReply(conn, 0x05, "0.0.0.0:0")
		return "", fmt.Errorf("Wrong SOCKS version: %d", header[0]), REQUEST_UNKNOWN_PROTO
	}

	cmd := header[1]

	if cmd != 0x01 && cmd != 0x03 {
		sendReply(conn, 0x07, "0.0.0.0:0") // Command Not Supported
		return "", fmt.Errorf("Only CONNECT and UDP ASSOCIATE are supported"), REQUEST_UNKNOWN_PROTO
	}

	atyp := header[3]
	var host string

	switch atyp {
	case 0x01: // IPv4
		ip := make([]byte, 4)
		if _, err := io.ReadFull(conn, ip); err != nil {
			return "", err, REQUEST_UNKNOWN_PROTO
		}
		host = net.IP(ip).String()
	case 0x03: // Domain Name
		var domainLen byte
		if err := binary.Read(conn, binary.BigEndian, &domainLen); err != nil {
			return "", err, REQUEST_UNKNOWN_PROTO
		}
		domain := make([]byte, domainLen)
		if _, err := io.ReadFull(conn, domain); err != nil {
			return "", err, REQUEST_UNKNOWN_PROTO
		}
		host = string(domain)
	case 0x04: // IPv6
		ip := make([]byte, 16)
		if _, err := io.ReadFull(conn, ip); err != nil {
			return "", err, REQUEST_UNKNOWN_PROTO
		}
		host = net.IP(ip).String()
	default:
		sendReply(conn, 0x08, "0.0.0.0:0") // Address Type Not Supported
		return "", fmt.Errorf("Unsupported addres type: %d", atyp), REQUEST_UNKNOWN_PROTO
	}

	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, portBuf); err != nil {
		return "", err, REQUEST_UNKNOWN_PROTO
	}
	port := binary.BigEndian.Uint16(portBuf)

	var reqProtoType RequestProto = REQUEST_UNKNOWN_PROTO
	switch cmd {
	case 0x01:
		reqProtoType = REQUEST_TCP
	case 0x03:
		reqProtoType = REQUEST_UDP
	}

	if reqProtoType == REQUEST_UNKNOWN_PROTO {
		return "", fmt.Errorf("Unknown protocol: %d", cmd), REQUEST_UNKNOWN_PROTO
	}

	return net.JoinHostPort(host, fmt.Sprintf("%d", port)), nil, reqProtoType
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
