package httpt

import (
	"io"
	"sync"
)

func TransparentProxy(clientConn, serverConn io.ReadWriteCloser) error {
	wg := sync.WaitGroup{}
	wg.Add(2)

	copyAndCloseWrite := func(dst io.WriteCloser, src io.ReadCloser) error {
		_, err := io.Copy(dst, src)
		if closeWriter, ok := dst.(interface {
			CloseWrite() error
		}); ok {
			closeWriter.CloseWrite()
		} else {
			dst.Close()
		}
		wg.Done()
		return err
	}

	go copyAndCloseWrite(serverConn, clientConn)
	err := copyAndCloseWrite(clientConn, serverConn)

	wg.Wait()
	return err
}
