//! We will write an injector here.
const std = @import("std");
const Io = std.Io;
const w = std.os.windows;
const w32 = @import("windows.zig");

const cheat_lib = @import("rws_cheat");

const PROCESS_NAME = "Project_P-Win64-Shipping.exe";
const DLL_PATH = "./cheat.dll";

pub fn main(init: std.process.Init) !void {
    const arena: std.mem.Allocator = init.arena.allocator();
    const io = init.io;

    const args = try init.minimal.args.toSlice(arena);
    for (args) |arg| {
        if (std.mem.eql(u8, arg, "-h") or std.mem.eql(u8, arg, "--help")) {
            std.debug.print("rws_cheat.exe <process name or PID> <path to DLL>\n", .{});

            return;
        }
    }

    const pid_or_name = if (args.len >= 2) args[1] else PROCESS_NAME;
    const path_to_dll = if (args.len >= 3) args[2] else DLL_PATH;

    // Check the file exists and we can access it.
    const file = try Io.Dir.cwd().openFile(io, path_to_dll, .{ .path_only = true });
    defer file.close(io);

    try inject(pid_or_name, path_to_dll);

    std.log.info("Injected DLL!", .{});
}

fn inject(pid_or_name: [:0]const u8, dll_path: [:0]const u8) !void {
    const pid = std.fmt.parseInt(w.DWORD, pid_or_name, 10) catch blk: {
        break :blk try getPidForName(pid_or_name);
    };

    std.log.info("PID: {d}", .{pid});
    std.log.info("DLL PATH: {s}", .{dll_path});

    // Get a handle
    const proc_handle = w32.OpenProcess(w32.PROCESS_ALL_ACCESS, .FALSE, pid) orelse {
        fail("OpenProcess");
        return error.OpenProcess;
    };
    defer if (w32.CloseHandle(proc_handle) == .FALSE) fail("CloseHandle (process)");

    // Allocate memory for the DLL load path.
    const path_ptr = w32.VirtualAllocEx(
        proc_handle,
        null,
        dll_path.len + 1,
        w32.MEM_COMMIT | w32.MEM_RESERVE,
        w32.PAGE_READWRITE,
    ) orelse {
        fail("VirtualAllocEx");
        return error.VirtualAllocEx;
    };
    defer if (w32.VirtualFreeEx(proc_handle, path_ptr, 0, w32.MEM_RELEASE) == 0) fail("VirtualFreeEx");

    // Write DLL path into target.
    if (w32.WriteProcessMemory(proc_handle, path_ptr, dll_path.ptr, dll_path.len + 1, null) == 0) {
        fail("WriteProcessMemory");
        return error.WriteProcessMemory;
    }

    // Get LoadLibraryA address.
    const kernel32 = w32.GetModuleHandleA("kernel32.dll") orelse {
        fail("GetModuleHandleA");
        return error.GetModuleHandleA;
    };
    const load_library_addr = w32.GetProcAddress(kernel32, "LoadLibraryA") orelse {
        fail("GetProcAddress");
        return error.GetProcAddress;
    };

    // Create a remote thread calling our function.
    const thread_handle = w32.CreateRemoteThread(
        proc_handle,
        null,
        0,
        @ptrCast(load_library_addr),
        path_ptr,
        0,
        null,
    ) orelse {
        fail("CreateRemoteThread");
        return error.CreateRemoteThread;
    };
    defer if (w32.CloseHandle(thread_handle) == .FALSE) fail("CloseHandle (thread)");

    if (w32.WaitForSingleObject(thread_handle, w32.INFINITE) == w32.WAIT_FAILED) {
        fail("WaitForSingleObject");
        return error.WaitForSingleObject;
    }

    var exit_status: w.DWORD = undefined;
    if (w32.GetExitCodeThread(
        thread_handle,
        &exit_status,
    ) == 0) {
        fail("GetExitCodeThread");
        return error.GetExitCodeThread;
    }

    if (exit_status != w32.STILL_ACTIVE) {
        std.log.err("The thread exited with status {d}.", .{exit_status});
    }
}

/// Logs `func` along with the calling thread's last Win32 error.
fn fail(comptime func: []const u8) void {
    const err = w.GetLastError();
    const name = std.enums.tagName(w.Win32Error, err) orelse "unknown";
    std.log.err(func ++ " failed: {s} ({d})", .{ name, @backingInt(err) });
}

/// Like `logLastError`, but at debug level and tagged with the PID being probed.
fn failDebug(comptime func: []const u8, pid: w.DWORD) void {
    const err = w.GetLastError();
    const name = std.enums.tagName(w.Win32Error, err) orelse "unknown";
    std.log.debug(func ++ " failed for PID {d}: {s} ({d})", .{ pid, name, @backingInt(err) });
}

fn getPidForName(name: [:0]const u8) !w.DWORD {
    var processes: [1024]w.DWORD = undefined;

    var cbNeeded: w.DWORD = 0;
    var cProcesses: w.DWORD = 0;

    if (w32.EnumProcesses(@ptrCast(&processes), @sizeOf(@TypeOf(processes)), &cbNeeded) == .FALSE) {
        fail("EnumProcesses");
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
    const proc_handle = w32.OpenProcess(
        w32.PROCESS_QUERY_INFORMATION | w32.PROCESS_VM_READ,
        w.BOOL.FALSE,
        pid,
    ) orelse {
        failDebug("OpenProcess", pid);
        return false;
    };
    defer if (w32.CloseHandle(proc_handle) == .FALSE) fail("CloseHandle");

    var module: [1]w.HMODULE = undefined;
    var cbNeeded: w.DWORD = 0;

    if (w32.EnumProcessModules(proc_handle, @ptrCast(&module), @sizeOf(@TypeOf(module)), &cbNeeded) == .FALSE) {
        failDebug("EnumProcessModules", pid);
        return false;
    }

    const len = w32.GetModuleBaseNameA(
        proc_handle,
        module[0],
        &process_name,
        process_name.len / @sizeOf(w.CHAR),
    );
    if (len == 0) {
        failDebug("GetModuleBaseNameA", pid);
        return false;
    }

    const name = process_name[0..len];

    return std.mem.eql(u8, name, expected);
}
