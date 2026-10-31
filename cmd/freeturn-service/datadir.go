package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
)

// dataDirSDDL: владелец администраторы, SYSTEM и администраторы полный доступ, права
// родителя не наследуются, файлы и папки внутри получают эти же права.
const dataDirSDDL = "O:BAD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"

// dataPaths - файлы службы. Каталог данных лежит в Program Files, а не в ProgramData: там
// обычный пользователь создаёт папки и переносит чужие на нужное место, и никакая проверка
// владельца не докажет, откуда каталог взялся. В Program Files ему не дано ни то, ни другое, как
// у WireGuard для Windows. Путь не зависит от того, где лежит exe.
type dataPaths struct {
	app, root, core, logs, state, lock string
}

// dataPathsFor строит пути от каталога Program Files: app - папка FreeTurn, root - её Data.
func dataPathsFor(programFiles string) dataPaths {
	app := filepath.Join(programFiles, "FreeTurn")
	root := filepath.Join(app, "Data")
	return dataPaths{
		app:   app,
		root:  root,
		core:  filepath.Join(root, "core"),
		logs:  filepath.Join(root, "logs"),
		state: filepath.Join(root, "state.json"),
		lock:  filepath.Join(root, "service.lock"),
	}
}

func programFilesDir() (string, error) {
	base, err := windows.KnownFolderPath(windows.FOLDERID_ProgramFiles, 0)
	if err != nil {
		return "", fmt.Errorf("каталог Program Files: %w", err)
	}
	return base, nil
}

// prepareDataDir создаёт каталоги и закрывает их от пользователей. Вызывается при каждом
// запуске и при установке раньше любого чтения из каталога.
func prepareDataDir() (dataPaths, error) {
	base, err := programFilesDir()
	if err != nil {
		return dataPaths{}, err
	}
	return prepareDataDirIn(base, dataDirSDDL)
}

// prepareDataDirIn делает то же в заданном каталоге с заданными правами: тест без повышения не
// может ни писать в Program Files, ни назвать владельцем администраторов.
func prepareDataDirIn(programFiles, sddl string) (dataPaths, error) {
	p := dataPathsFor(programFiles)
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return dataPaths{}, err
	}
	if err := os.MkdirAll(p.app, 0o755); err != nil {
		return dataPaths{}, fmt.Errorf("каталог службы: %w", err)
	}
	if err := secureDir(p.root, sd); err != nil {
		return dataPaths{}, fmt.Errorf("каталог данных: %w", err)
	}
	// Вложенные каталоги создаются уже внутри закрытого и получают его права.
	for _, dir := range []string{p.core, p.logs} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return dataPaths{}, fmt.Errorf("каталог данных: %w", err)
		}
	}
	return p, nil
}

// secureDir приводит dir к закрытому состоянию. Новый каталог сразу создаётся с нужными правами
// и не бывает открытым ни мгновения, существующему права ставятся заново.
func secureDir(dir string, sd *windows.SECURITY_DESCRIPTOR) error {
	path, err := windows.UTF16PtrFromString(dir)
	if err != nil {
		return err
	}
	sa := windows.SecurityAttributes{SecurityDescriptor: sd}
	sa.Length = uint32(unsafe.Sizeof(sa))
	err = windows.CreateDirectory(path, &sa)
	if !errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
		return err
	}
	return resetDACL(path, sd)
}

// resetDACL ставит существующему каталогу права через его дескриптор. Ссылка открывается как
// ссылка и отклоняется: права легли бы на то, куда она указывает.
func resetDACL(path *uint16, sd *windows.SECURITY_DESCRIPTOR) error {
	const (
		access = windows.READ_CONTROL | windows.WRITE_DAC | windows.FILE_READ_ATTRIBUTES
		share  = windows.FILE_SHARE_READ | windows.FILE_SHARE_WRITE
		flags  = windows.FILE_FLAG_OPEN_REPARSE_POINT | windows.FILE_FLAG_BACKUP_SEMANTICS
	)
	h, err := windows.CreateFile(path, access, share, nil, windows.OPEN_EXISTING, flags, 0)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(h)

	var attrs windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(h, &attrs); err != nil {
		return err
	}
	if attrs.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return errors.New("на месте каталога ссылка")
	}
	if attrs.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0 {
		return errors.New("на месте каталога файл")
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	const info = windows.DACL_SECURITY_INFORMATION | windows.PROTECTED_DACL_SECURITY_INFORMATION
	return windows.SetSecurityInfo(h, windows.SE_FILE_OBJECT, info, nil, nil, dacl, nil)
}

// lockInstance не даёт запустить второй экземпляр. RemoveStale удалил бы адаптер работающей
// службы, если запустить console рядом с ней, поэтому блокировка берётся раньше него. Файл
// открыт без совместного доступа на время жизни процесса, при падении дескриптор закрывает ядро
// системы. Он лежит в закрытом каталоге данных, поэтому пользователь занять его не может.
func lockInstance(path string) (release func(), err error) {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	h, err := windows.CreateFile(name, windows.GENERIC_WRITE, 0, nil, windows.OPEN_ALWAYS, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return nil, fmt.Errorf("другой экземпляр службы уже работает: %w", err)
	}
	return func() { windows.CloseHandle(h) }, nil
}
