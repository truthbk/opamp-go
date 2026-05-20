package internal

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/open-telemetry/opamp-go/client/types"
	"github.com/open-telemetry/opamp-go/internal"
	"github.com/open-telemetry/opamp-go/protobufs"
	"github.com/open-telemetry/opamp-go/signing"
)

// wsReceiver implements the WebSocket client's receiving portion of OpAMP protocol.
type wsReceiver struct {
	conn      *websocket.Conn
	logger    types.Logger
	sender    *WSSender
	callbacks types.Callbacks
	processor receivedProcessor

	// attestation, when non-nil, decodes inbound messages as
	// SignedServerToAgent envelopes, validates the trust chain on the
	// first message, verifies the signature on subsequent ones, and
	// surfaces the inner ServerToAgent for normal processing.
	attestation *attestationState

	// Indicates that the receiver has fully stopped.
	stopped chan struct{}
}

// NewWSReceiver creates a new Receiver that uses WebSocket to receive
// messages from the server. If payloadVerifier is non-nil, every
// inbound message is treated as a SignedServerToAgent envelope: the
// trust chain is validated on the first message, signatures are
// verified on every subsequent one, and any failure terminates the
// receive loop (and, by extension, the connection). When
// payloadVerifier is nil, the receiver uses the standard ServerToAgent
// wire format (identical to upstream OpAMP).
func NewWSReceiver(
	logger types.Logger,
	callbacks types.Callbacks,
	conn *websocket.Conn,
	sender *WSSender,
	clientSyncedState *ClientSyncedState,
	packagesStateProvider types.PackagesStateProvider,
	packageSyncMutex *sync.Mutex,
	reporterInterval time.Duration,
	payloadVerifier signing.Verifier,
) *wsReceiver {
	w := &wsReceiver{
		conn:      conn,
		logger:    logger,
		sender:    sender,
		callbacks: callbacks,
		processor: newReceivedProcessor(logger, callbacks, sender, clientSyncedState, packagesStateProvider, packageSyncMutex, reporterInterval),
		stopped:   make(chan struct{}),
	}
	if payloadVerifier != nil {
		w.attestation = newAttestationState(payloadVerifier)
	}

	return w
}

// Start starts the receiver loop.
func (r *wsReceiver) Start(ctx context.Context) {
	go r.ReceiverLoop(ctx)
}

// IsStopped returns a channel that's closed when the receiver is stopped.
func (r *wsReceiver) IsStopped() <-chan struct{} {
	return r.stopped
}

// ReceiverLoop runs the receiver loop.
// To stop the receiver cancel the context and close the websocket connection
func (r *wsReceiver) ReceiverLoop(ctx context.Context) {
	type receivedMessage struct {
		message *protobufs.ServerToAgent
		err     error
	}

	defer func() { close(r.stopped) }()

	for {
		select {
		case <-ctx.Done():
			return
		default:
			result := make(chan receivedMessage, 1)

			// To stop this goroutine, close the websocket connection
			go func() {
				var message protobufs.ServerToAgent
				err := r.receiveMessage(ctx, &message)
				result <- receivedMessage{&message, err}
			}()

			select {
			case <-ctx.Done():
				return
			case res := <-result:
				if res.err != nil {
					if !websocket.IsCloseError(res.err, websocket.CloseNormalClosure) {
						r.logger.Errorf(ctx, "Unexpected error while receiving: %v", res.err)
					}
					return
				}
				r.processor.ProcessReceivedMessage(ctx, res.message)
			}
		}
	}
}

func (r *wsReceiver) receiveMessage(ctx context.Context, msg *protobufs.ServerToAgent) error {
	mt, bytes, err := r.conn.ReadMessage()
	if err != nil {
		return err
	}
	if mt != websocket.BinaryMessage {
		return fmt.Errorf("unsupported message type: %v", mt)
	}
	protoBytes, err := internal.StripWSMessageHeader(bytes)
	if err != nil {
		return fmt.Errorf("cannot decode received message: %w", err)
	}
	if err := unwrapServerToAgent(ctx, r.attestation, protoBytes, msg); err != nil {
		return fmt.Errorf("cannot decode received message: %w", err)
	}
	return nil
}
