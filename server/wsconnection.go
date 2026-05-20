package server

import (
	"context"
	"net"
	"sync"
	"sync/atomic"

	"github.com/gorilla/websocket"

	"github.com/open-telemetry/opamp-go/internal"
	"github.com/open-telemetry/opamp-go/protobufs"
	"github.com/open-telemetry/opamp-go/server/types"
)

// wsConnection represents a persistent OpAMP connection over a WebSocket.
type wsConnection struct {
	// The websocket library does not allow multiple concurrent write operations,
	// so ensure that we only have a single operation in progress at a time.
	// For more: https://pkg.go.dev/github.com/gorilla/websocket#hdr-Concurrency
	connMutex sync.Mutex
	wsConn    *websocket.Conn
	closed    atomic.Bool

	// signing, when non-nil, indicates that this connection has
	// negotiated payload trust verification with the Agent. Outbound
	// ServerToAgent messages are wrapped in a SignedServerToAgent
	// envelope and the first send carries the trust chain.
	signing *connectionSigningState
}

var _ types.Connection = (*wsConnection)(nil)

func newWSConnection(wsConn *websocket.Conn) *wsConnection {
	return &wsConnection{wsConn: wsConn}
}

// enableSigning marks this connection as one that has negotiated
// payload trust verification. Outbound Send calls will wrap their
// ServerToAgent argument in a SignedServerToAgent envelope using the
// supplied state. Must be called before the first Send.
func (c *wsConnection) enableSigning(state *connectionSigningState) {
	c.signing = state
}

func (c *wsConnection) Connection() net.Conn {
	return c.wsConn.UnderlyingConn()
}

func (c *wsConnection) Send(ctx context.Context, message *protobufs.ServerToAgent) error {
	c.connMutex.Lock()
	defer c.connMutex.Unlock()

	if c.signing != nil {
		env, err := c.signing.signOutgoing(ctx, message)
		if err != nil {
			return err
		}
		return internal.WriteWSMessage(c.wsConn, env)
	}

	return internal.WriteWSMessage(c.wsConn, message)
}

func (c *wsConnection) Disconnect() error {
	if !c.closed.CompareAndSwap(false, true) {
		return nil
	}
	return c.wsConn.Close()
}
