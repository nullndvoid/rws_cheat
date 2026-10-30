//! Helpful extern function definitions for various Windows API functions.
const w = @import("std").os.windows;

pub extern "kernel32" fn OpenProcess(
    dwDesiredAccess: w.DWORD,
    bInheritHandle: w.BOOL,
    dwProcessId: w.DWORD,
) callconv(.winapi) ?w.HANDLE;

pub extern "kernel32" fn CloseHandle(hObject: w.HANDLE) callconv(.winapi) w.BOOL;

/// `lpidProcess` is out pointer to an array of process IDs.
/// `cb` is size of out array in bytes.
/// `lpcbNeeded` is size written out, in bytes.
pub extern "psapi" fn EnumProcesses(
    lpidProcess: [*]w.DWORD,
    cb: w.DWORD,
    lpcbNeeded: *w.DWORD,
) callconv(.winapi) w.BOOL;

/// `lphModule` is out pointer to an array of module handles.
/// `cb` is size of out array in bytes.
/// `lpcbNeeded` is size written out, in bytes.
pub extern "psapi" fn EnumProcessModules(
    hProcess: w.HANDLE,
    lphModule: [*]w.HMODULE,
    cb: w.DWORD,
    lpcbNeeded: *w.DWORD,
) callconv(.winapi) w.BOOL;

/// Returns the number of characters copied (excluding the NUL), or 0 on failure.
/// A null `hModule` means the process's main executable.
pub extern "psapi" fn GetModuleBaseNameA(
    hProcess: w.HANDLE,
    hModule: ?w.HMODULE,
    lpBaseName: [*]u8,
    nSize: w.DWORD,
) callconv(.winapi) w.DWORD;

pub const PROCESS_QUERY_INFORMATION: w.DWORD = 0x0400;
pub const PROCESS_VM_READ: w.DWORD = 0x0010;
