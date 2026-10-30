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

    const args = try init.minimal.args.toSlice(arena);
    for (args) |arg| {
        if (std.mem.eql(u8, arg, "-h") or std.mem.eql(u8, arg, "--help")) {
            std.debug.print("rws_cheat.exe <process name or PID> <path to DLL>\n", .{});

            return;
        }
    }

    const pid_or_name = if (args.len >= 2) args[1] else PROCESS_NAME;
    const path_to_dll = if (args.len >= 3) args[2] else DLL_PATH;

    try inject(pid_or_name, path_to_dll);
}

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

    if (w32.EnumProcesses(@ptrCast(&processes), @sizeOf(@TypeOf(processes)), &cbNeeded) == .FALSE) {
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
    const proc_handle = w32.OpenProcess(w32.PROCESS_QUERY_INFORMATION | w32.PROCESS_VM_READ, w.BOOL.FALSE, pid);
    defer if (proc_handle) |h| {
        _ = w32.CloseHandle(h);
    };

    if (proc_handle == null) {
        return false; // maybe return errors if we need.
    }

    var module: [1]w.HMODULE = undefined;
    var cbNeeded: w.DWORD = 0;

    var len: usize = 0;

    if (w32.EnumProcessModules(proc_handle.?, @ptrCast(&module), 8, &cbNeeded) != .FALSE) {
        len = w32.GetModuleBaseNameA(proc_handle.?, module[0], &process_name, process_name.len / @sizeOf(w.CHAR));
    }

    if (len == 0)
        return false; // maybe return errors?

    const name = process_name[0..len];

    return std.mem.eql(u8, name, expected);
}
