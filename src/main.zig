const std = @import("std");
const Io = std.Io;
const w = std.os.windows;

const cheat_lib = @import("RWS_CHEAT_LIB");

const PROCESS_NAME = "Project_P-Win64-Shipping.exe";
const DLL_PATH = "./cheat.dll";

// We will write an injector here.
pub fn main(init: std.process.Init) !void {
    const io = init.io;
    _ = io; // autofix
    const arena: std.mem.Allocator = init.arena.allocator();

    const args = try init.minimal.args.toSlice(arena);
    for (args) |arg| {
        if (std.mem.eql(u8, arg, "-h") or std.mem.eql(u8, arg, "--help")) {
            std.debug.print("rws_cheat <process name or PID> <path to DLL>\n", .{});

            return;
        }
    }

    const pid_or_name = if (args.len >= 2) args[1] else null orelse PROCESS_NAME;
    const path_to_dll = if (args.len >= 3) args[2] else null orelse DLL_PATH;

    try inject(pid_or_name, path_to_dll);
}

extern "kernel32" fn OpenProcess(
    dwDesiredAccess: w.DWORD,
    bInheritHandle: w.BOOL,
    dwProcessId: w.DWORD,
) callconv(.winapi) ?w.HANDLE;

extern "kernel32" fn CloseHandle(hObject: w.HANDLE) callconv(.winapi) w.BOOL;

/// `lpidProcess` is out pointer to an array of process IDs.
/// `cb` is size of out array in bytes.
/// `lpcbNeeded` is size written out, in bytes.
extern "psapi" fn EnumProcesses(
    lpidProcess: [*]w.DWORD,
    cb: w.DWORD,
    lpcbNeeded: *w.DWORD,
) callconv(.winapi) w.BOOL;

/// `lphModule` is out pointer to an array of module handles.
/// `cb` is size of out array in bytes.
/// `lpcbNeeded` is size written out, in bytes.
extern "psapi" fn EnumProcessModules(
    hProcess: w.HANDLE,
    lphModule: [*]w.HMODULE,
    cb: w.DWORD,
    lpcbNeeded: *w.DWORD,
) callconv(.winapi) w.BOOL;

/// Returns the number of characters copied (excluding the NUL), or 0 on failure.
/// A null `hModule` means the process's main executable.
extern "psapi" fn GetModuleBaseNameA(
    hProcess: w.HANDLE,
    hModule: ?w.HMODULE,
    lpBaseName: [*]u8,
    nSize: w.DWORD,
) callconv(.winapi) w.DWORD;

const PROCESS_QUERY_INFORMATION: w.DWORD = 0x0400;
const PROCESS_VM_READ: w.DWORD = 0x0010;

fn inject(pid_or_name: [:0]const u8, dll_path: [:0]const u8) !void {
    const pid = std.fmt.parseInt(w.DWORD, pid_or_name, 10) catch blk: {
        break :blk try getPidForName(pid_or_name);
    };

    std.debug.print("PID: {d}\n", .{pid});
    std.debug.print("DLL PATH: {s}\n", .{dll_path});

    // Get a handle
}

fn getPidForName(name: [:0]const u8) !w.DWORD {
    var processes: [1024]w.DWORD = undefined;

    var cbNeeded: w.DWORD = 0;
    var cProcesses: w.DWORD = 0;

    if (EnumProcesses(@ptrCast(&processes), @sizeOf(@TypeOf(processes)), &cbNeeded) == .FALSE) {
        return error.EnumProcesses;
    }

    cProcesses = cbNeeded / @sizeOf(w.DWORD);

    for (processes[0..cProcesses]) |proc| {
        if (proc == 0) continue;

        if (!try checkProcessName(proc, name)) continue;

        return proc;
    }

    return error.NoSuchProcess;
}

fn checkProcessName(pid: u32, expected: [:0]const u8) !bool {
    var process_name: [w.MAX_PATH:0]w.CHAR = @splat(0);
    const proc_handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, w.BOOL.FALSE, pid);
    defer if (proc_handle) |h| {
        _ = CloseHandle(h);
    };

    if (proc_handle == null) {
        return false; // maybe return errors if we need.
    }

    var module: [1]w.HMODULE = undefined;
    var cbNeeded: w.DWORD = 0;

    var len: usize = 0;

    if (EnumProcessModules(proc_handle.?, @ptrCast(&module), 8, &cbNeeded) != .FALSE) {
        len = GetModuleBaseNameA(proc_handle.?, module[0], &process_name, process_name.len / @sizeOf(w.CHAR));
    }

    if (len == 0)
        return false; // maybe return errors?

    const name = process_name[0..len];

    return std.mem.eql(u8, name, expected);
}
