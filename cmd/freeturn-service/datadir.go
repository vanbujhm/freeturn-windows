package main

import (
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	// dataDirSDDL: владелец администраторы, SYSTEM и администраторы полный доступ, права
	// родителя не наследуются, файлы и папки внутри получают эти же права.
	dataDirSDDL = "O:BAD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"
	// secureAttempts - сколько раз secure пробует занять место подброшенного каталога.
	secureAttempts = 3
	// asideInfix стоит в имени подброшенного каталога, который отодвинут в сторону.
	asideInfix = ".planted-"
)

// dataPaths - файлы службы в %ProgramData%.
type dataPaths struct {
	root, core, logs, state, lock string
}

func dataPathsFor(programData string) dataPaths {
	root := filepath.Join(programData, "FreeTurn")
	return dataPaths{
		root:  root,
		core:  filepath.Join(root, "core"),
		logs:  filepath.Join(root, "logs"),
		state: filepath.Join(root, "state.json"),
		lock:  filepath.Join(root, "service.lock"),
	}
}

func programDataPaths() (dataPaths, error) {
	base, err := windows.KnownFolderPath(windows.FOLDERID_ProgramData, 0)
	if err != nil {
		return dataPaths{}, fmt.Errorf("каталог ProgramData: %w", err)
	}
	return dataPathsFor(base), nil
}

// prepareDataDir создаёт каталоги и закрывает их от пользователей. Вызывается при каждом
// запуске и при установке раньше любого чтения из каталога. Создать папку в ProgramData может
// любой пользователь, поэтому сбой здесь останавливает запуск: файлам в таком каталоге верить
// нельзя. Непустая заметка сообщает, что каталог пришлось заменить.
func prepareDataDir() (dataPaths, string, error) {
	p, err := programDataPaths()
	if err != nil {
		return dataPaths{}, "", err
	}
	note, err := serviceDir.secure(p.root)
	if err != nil {
		return dataPaths{}, note, fmt.Errorf("каталог службы: %w", err)
	}
	// Вложенные каталоги создаются уже внутри закрытого и получают его права.
	for _, dir := range []string{p.core, p.logs} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return dataPaths{}, note, fmt.Errorf("каталог службы: %w", err)
		}
	}
	return p, note, nil
}

// dirPolicy описывает закрытый каталог: какие права ему ставить и кому из владельцев верить.
type dirPolicy struct {
	sddl    string
	trusted func(*windows.SID) bool
}

var serviceDir = dirPolicy{sddl: dataDirSDDL, trusted: trustedOwner}

// trustedOwner: каталог создан службой или установщиком. Владельцем становится только тот, кто
// создал объект или получил такое право, поэтому обычный пользователь сюда не попадёт.
func trustedOwner(owner *windows.SID) bool {
	return owner.IsWellKnown(windows.WinLocalSystemSid) || owner.IsWellKnown(windows.WinBuiltinAdministratorsSid)
}

// secure приводит root к закрытому состоянию. Новый каталог сразу создаётся с нужными правами и
// не бывает открытым ни мгновения. Существующий проверяется по дескриптору, а подброшенный
// заменяется целиком: вложенная папка со своими правами пережила бы любую смену прав снаружи.
// Повтор нужен, если каталог успели подбросить снова.
func (d dirPolicy) secure(root string) (note string, err error) {
	sd, err := windows.SecurityDescriptorFromString(d.sddl)
	if err != nil {
		return "", err
	}
	for range secureAttempts {
		err := createProtected(root, sd)
		if !errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
			return note, err
		}
		planted, err := d.adopt(root, sd)
		if err != nil {
			return note, err
		}
		if !planted {
			return note, nil
		}
		if note, err = evict(root); err != nil {
			return note, err
		}
	}
	return note, errors.New("его снова и снова создаёт кто-то другой")
}

func createProtected(root string, sd *windows.SECURITY_DESCRIPTOR) error {
	path, err := windows.UTF16PtrFromString(root)
	if err != nil {
		return err
	}
	sa := windows.SecurityAttributes{SecurityDescriptor: sd}
	sa.Length = uint32(unsafe.Sizeof(sa))
	return windows.CreateDirectory(path, &sa)
}

// adopt проверяет существующий root и ставит ему права. Всё идёт через один дескриптор: он
// открыт без FILE_SHARE_DELETE, поэтому объект нельзя подменить между проверкой и записью прав,
// а ссылка открывается как ссылка и не ведёт за собой. true: каталог подброшен. Отказ в доступе
// это тоже подброшенный каталог: у законного владельца право прочитать и сменить права есть
// всегда, а значит, владелец другой.
func (d dirPolicy) adopt(root string, sd *windows.SECURITY_DESCRIPTOR) (planted bool, err error) {
	path, err := windows.UTF16PtrFromString(root)
	if err != nil {
		return false, err
	}
	const (
		access = windows.READ_CONTROL | windows.WRITE_DAC | windows.FILE_READ_ATTRIBUTES
		share  = windows.FILE_SHARE_READ | windows.FILE_SHARE_WRITE
		flags  = windows.FILE_FLAG_OPEN_REPARSE_POINT | windows.FILE_FLAG_BACKUP_SEMANTICS
	)
	h, err := windows.CreateFile(path, access, share, nil, windows.OPEN_EXISTING, flags, 0)
	if errors.Is(err, windows.ERROR_ACCESS_DENIED) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	defer windows.CloseHandle(h)

	var attrs windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(h, &attrs); err != nil {
		return false, err
	}
	if attrs.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 ||
		attrs.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0 {
		return true, nil
	}
	current, err := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return false, err
	}
	owner, _, err := current.Owner()
	if err != nil {
		return false, err
	}
	if !d.trusted(owner) {
		return true, nil
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return false, err
	}
	const info = windows.DACL_SECURITY_INFORMATION | windows.PROTECTED_DACL_SECURITY_INFORMATION
	return false, windows.SetSecurityInfo(h, windows.SE_FILE_OBJECT, info, nil, nil, dacl, nil)
}

// evict убирает подброшенный root: сначала отодвигает, потом удаляет. Так каталог уходит и тогда,
// когда пользователь закрыл его от всех. Удаление идёт через os.RemoveAll, он ссылки не раскрывает.
// Если удалить не вышло, остаток лежит под другим именем и службе не мешает.
func evict(root string) (note string, err error) {
	aside := root + asideInfix + rand.Text()
	if err := renameBeside(root, aside); err != nil {
		return "", fmt.Errorf("чужой каталог не убран: %w", err)
	}
	// RemoveAll молча принимает несуществующий путь, а ответ об удалении должен быть правдой.
	if _, err := os.Lstat(aside); err != nil {
		return "", fmt.Errorf("чужой каталог не убран: %w", err)
	}
	if err := os.RemoveAll(aside); err != nil {
		return fmt.Sprintf("чужой каталог службы отодвинут, но не удалён: %s: %v", aside, err), nil
	}
	return "чужой каталог службы удалён", nil
}

// fileRenameInfo - FILE_RENAME_INFORMATION, имя задано массивом.
type fileRenameInfo struct {
	flags         uint32
	rootDirectory windows.Handle
	nameLength    uint32
	name          [1024]uint16
}

// renameBeside переименовывает объект, ссылка переименовывается сама. Оба пути полные: короткое
// имя в SetFileInformationByHandle считалось бы от рабочего каталога процесса и увело бы объект
// туда. DELETE даёт FILE_DELETE_CHILD у родителя, даже если сам объект закрыт. Другие права дал
// бы только объект, а MoveFileEx и CreateFile их просят всегда, поэтому открытие идёт через
// NtCreateFile с одним DELETE.
func renameBeside(path, target string) error {
	nt, err := windows.NewNTUnicodeString(`\??\` + path)
	if err != nil {
		return err
	}
	attrs := windows.OBJECT_ATTRIBUTES{ObjectName: nt, Attributes: windows.OBJ_CASE_INSENSITIVE}
	attrs.Length = uint32(unsafe.Sizeof(attrs))
	const (
		share   = windows.FILE_SHARE_READ | windows.FILE_SHARE_WRITE | windows.FILE_SHARE_DELETE
		options = windows.FILE_OPEN_FOR_BACKUP_INTENT | windows.FILE_OPEN_REPARSE_POINT
	)
	var (
		h    windows.Handle
		iosb windows.IO_STATUS_BLOCK
	)
	err = windows.NtCreateFile(&h, windows.DELETE, &attrs, &iosb, nil, 0, share, windows.FILE_OPEN, options, 0, 0)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(h)

	name, err := windows.UTF16FromString(`\??\` + target)
	if err != nil {
		return err
	}
	name = name[:len(name)-1] // длина задаётся явно, ноль не нужен
	var info fileRenameInfo
	if len(name) > len(info.name) {
		return fmt.Errorf("слишком длинный путь: %s", target)
	}
	info.nameLength = uint32(len(name) * 2)
	copy(info.name[:], name)
	return windows.NtSetInformationFile(h, &iosb, (*byte)(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info)), windows.FileRenameInformation)
}

// lockInstance не даёт запустить второй экземпляр. RemoveStale удалил бы адаптер работающей
// службы, если запустить console рядом с ней, поэтому блокировка берётся раньше него. Файл
// открыт без совместного доступа на время жизни процесса, при падении дескриптор закрывает ядро
// системы. Он лежит в закрытом каталоге, поэтому пользователь занять его не может.
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
