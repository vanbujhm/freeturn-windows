package profile

import (
	"errors"
	"unsafe"

	"golang.org/x/sys/windows"
)

// dpapiFunc общая форма CryptProtectData и CryptUnprotectData.
type dpapiFunc func(in *windows.DataBlob, flags uint32, out *windows.DataBlob) error

// protect шифрует данные через DPAPI под текущего пользователя. Диалогов нет:
// CRYPTPROTECT_UI_FORBIDDEN, и там, где без диалога нельзя, вызов вернёт ошибку.
func protect(data []byte) ([]byte, error) {
	return callDPAPI(data, func(in *windows.DataBlob, flags uint32, out *windows.DataBlob) error {
		return windows.CryptProtectData(in, nil, nil, 0, nil, flags, out)
	})
}

// unprotect расшифровывает данные, зашифрованные protect тем же пользователем.
func unprotect(data []byte) ([]byte, error) {
	return callDPAPI(data, func(in *windows.DataBlob, flags uint32, out *windows.DataBlob) error {
		return windows.CryptUnprotectData(in, nil, nil, 0, nil, flags, out)
	})
}

func callDPAPI(data []byte, fn dpapiFunc) ([]byte, error) {
	if len(data) == 0 {
		return nil, errors.New("пустые данные")
	}
	in := windows.DataBlob{Size: uint32(len(data)), Data: &data[0]}
	var out windows.DataBlob
	if err := fn(&in, windows.CRYPTPROTECT_UI_FORBIDDEN, &out); err != nil {
		return nil, err
	}
	// Выходной буфер выделен системой: копия в память Go, затем освобождение.
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(out.Data)))
	return append([]byte(nil), unsafe.Slice(out.Data, out.Size)...), nil
}
