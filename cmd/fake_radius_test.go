package cmd

import (
	"crypto/hmac"
	"crypto/md5"
	"encoding/binary"
	"net"
	"testing"
)

// A minimal RADIUS responder, enough to exercise the whole output pipeline
// without a real server. It only has to produce replies the client accepts,
// which means getting the Response Authenticator right.
//
// Packet layout (RFC 2865): code, identifier, 2 byte length, 16 byte
// authenticator, then attributes.
const (
	radiusHeaderLen            = 20
	attrTypeMessageAuthenticat = 80
	codeAccessAccept           = 2
	codeAccessReject           = 3
)

type fakeServer struct {
	conn *net.UDPConn
	// replyCode is the code to answer with; 0 means never answer, which is how
	// the timeout path is exercised.
	replyCode byte
	secret    string
	// includeMA adds a Message-Authenticator, which Status replies require.
	includeMA bool
	requests  chan []byte
}

// startFakeServer listens on loopback and answers until the test finishes.
func startFakeServer(t *testing.T, secret string, replyCode byte, includeMA bool) *fakeServer {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	s := &fakeServer{
		conn:      conn,
		replyCode: replyCode,
		secret:    secret,
		includeMA: includeMA,
		requests:  make(chan []byte, 16),
	}
	t.Cleanup(func() { _ = conn.Close() })
	go s.serve()
	return s
}

func (s *fakeServer) port() int {
	return s.conn.LocalAddr().(*net.UDPAddr).Port
}

func (s *fakeServer) serve() {
	buf := make([]byte, 4096)
	for {
		n, addr, err := s.conn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		if n < radiusHeaderLen {
			continue
		}
		req := make([]byte, n)
		copy(req, buf[:n])
		select {
		case s.requests <- req:
		default:
		}
		if s.replyCode == 0 {
			continue
		}
		_, _ = s.conn.WriteToUDP(s.reply(req), addr)
	}
}

// reply builds an answer the client will accept.
func (s *fakeServer) reply(req []byte) []byte {
	id := req[1]
	reqAuth := req[4:radiusHeaderLen]

	var attrs []byte
	maOffset := -1
	if s.includeMA {
		maOffset = radiusHeaderLen + 2
		attrs = append(attrs, attrTypeMessageAuthenticat, 18)
		attrs = append(attrs, make([]byte, md5.Size)...)
	}

	pkt := make([]byte, radiusHeaderLen+len(attrs))
	pkt[0] = s.replyCode
	pkt[1] = id
	binary.BigEndian.PutUint16(pkt[2:4], uint16(len(pkt)))
	// The Message-Authenticator and the Response Authenticator are both
	// computed with the request authenticator in the header.
	copy(pkt[4:radiusHeaderLen], reqAuth)
	copy(pkt[radiusHeaderLen:], attrs)

	if maOffset >= 0 {
		mac := hmac.New(md5.New, []byte(s.secret))
		mac.Write(pkt)
		copy(pkt[maOffset:maOffset+md5.Size], mac.Sum(nil))
	}

	h := md5.New()
	h.Write(pkt)
	h.Write([]byte(s.secret))
	copy(pkt[4:radiusHeaderLen], h.Sum(nil))
	return pkt
}
