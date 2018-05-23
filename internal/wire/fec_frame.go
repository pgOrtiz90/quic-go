package wire

import (
	"bytes"
	"github.com/lucas-clemente/quic-go/internal/protocol"
)

// An FEC frame
type FecFrame struct {
	Data           []byte
}

// Write writes a STREAM frame
func (f *FecFrame) Write(b *bytes.Buffer, version protocol.VersionNumber) error {
	b.Write(f.Data)
	return nil
}


func (f *FecFrame) Length(version protocol.VersionNumber) protocol.ByteCount {
	return protocol.ByteCount(len(f.Data))
}