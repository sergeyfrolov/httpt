package httpt

import (
	"crypto/rand"
	"encoding/binary"
	"io"
	"sync"
)

func TransparentProxy(clientConn, serverConn io.ReadWriteCloser) error {
	wg := sync.WaitGroup{}
	wg.Add(2)

	copyAndCloseWrite := func(dst io.WriteCloser, src io.ReadCloser) error {
		io.Copy(dst, src)
		wg.Done()
		if closeWriter, ok := dst.(interface {
			CloseWrite() error
		}); ok {
			return closeWriter.CloseWrite()
		} else {
			return dst.Close()
		}
	}

	go copyAndCloseWrite(serverConn, clientConn)
	err := copyAndCloseWrite(clientConn, serverConn)

	wg.Wait()
	return err
}

func RandUint64Unwrap() uint64 {
	b := make([]byte, 8)
	_, err := rand.Read(b)
	if err != nil {
		panic(err)
	}
	return binary.LittleEndian.Uint64(b)
}
