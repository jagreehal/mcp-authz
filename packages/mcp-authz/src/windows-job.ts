import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

/** Quote one argument for CreateProcessW's command line (not a shell). */
export function quoteWindowsArgument(value: string): string {
  return `"${value.replace(/(\\*)"/g, '$1$1\\"').replace(/(\\+)$/, '$1$1')}"`;
}

/**
 * A PowerShell supervisor owns a kill-on-close Job Object. A small Node
 * launcher enters it while suspended, before it can create any descendants.
 * The supervisor keeps its handle until the launcher exits; closing it kills
 * every remaining descendant, even after their immediate parent has exited.
 * Only the supervisor owns the handle, so terminating it also kills the job.
 */
export function windowsJobCommand(command: string, args: readonly string[]) {
  const crossSpawn = createRequire(import.meta.url).resolve('cross-spawn');
  // The server's command and arguments travel in a file, not on a command
  // line: wrapped twice in Base64 they grow about sevenfold, and CreateProcessW
  // refuses anything over 32,767 characters. The file sits in a directory of
  // its own under the user's temp directory, and the launcher deletes it as
  // soon as it has read it, since arguments can carry credentials.
  const directory = mkdtempSync(join(tmpdir(), 'mcp-authz-job-'));
  const specPath = join(directory, 'spec.json');
  writeFileSync(specPath, JSON.stringify({ command, args }), { mode: 0o600 });
  const cleanup = () => rmSync(directory, { recursive: true, force: true });
  const launcher = [
    `const fs = require('fs');`,
    `const spawn = require(${JSON.stringify(crossSpawn)});`,
    `const spec = JSON.parse(fs.readFileSync(${JSON.stringify(specPath)}, 'utf8'));`,
    `fs.rmSync(${JSON.stringify(directory)}, { recursive: true, force: true });`,
    `const child = spawn(spec.command, spec.args, { stdio: 'inherit' });`,
    `child.on('error', error => { console.error(error.message); process.exit(1); });`,
    `child.on('exit', code => process.exit(code ?? 1));`,
  ].join('\n');
  const commandLine = [process.execPath, '--input-type=commonjs', '-e', launcher]
    .map(quoteWindowsArgument)
    .join(' ');
  // Neither a user command nor an argument becomes PowerShell source.
  const encoded = Buffer.from(commandLine, 'utf8').toString('base64');
  const script = [
    '$ErrorActionPreference = "Stop"',
    // Add-Type reports compile progress, and with stderr redirected PowerShell
    // writes it there as CLIXML, which reads as the server's own error output.
    "$ProgressPreference = 'SilentlyContinue'",
    "Add-Type -TypeDefinition @'",
    JOB_SUPERVISOR,
    "'@",
    `$line = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('${encoded}'))`,
    'try { exit ([McpAuthzJob]::Run($line)) }',
    'catch { [Console]::Error.WriteLine($_.Exception.Message); exit 1 }',
  ].join('\n');
  return {
    specPath,
    /** Remove the spec if the launcher never got to; safe to call twice. */
    cleanup,
    command: join(
      process.env.SystemRoot ?? 'C:\\Windows',
      'System32',
      'WindowsPowerShell',
      'v1.0',
      'powershell.exe',
    ),
    args: [
      '-NoLogo',
      '-NoProfile',
      '-NonInteractive',
      '-EncodedCommand',
      Buffer.from(script, 'utf16le').toString('base64'),
    ],
  };
}

// Windows PowerShell 5.1's C# compiler supports these declarations. Pointer-
// sized fields keep the native structures correct on both 32 and 64 bit hosts.
const JOB_SUPERVISOR = String.raw`
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;

public static class McpAuthzJob {
    [StructLayout(LayoutKind.Sequential)]
    struct BasicLimits {
        public long ProcessTime, JobTime;
        public uint Flags;
        public UIntPtr MinimumWorkingSet, MaximumWorkingSet;
        public uint ActiveProcessLimit;
        public UIntPtr Affinity;
        public uint PriorityClass, SchedulingClass;
    }
    [StructLayout(LayoutKind.Sequential)]
    struct IoCounters { public ulong ReadOps, WriteOps, OtherOps, ReadBytes, WriteBytes, OtherBytes; }
    [StructLayout(LayoutKind.Sequential)]
    struct ExtendedLimits {
        public BasicLimits Basic;
        public IoCounters Io;
        public UIntPtr ProcessMemory, JobMemory, PeakProcessMemory, PeakJobMemory;
    }
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct StartupInfo {
        public uint Size;
        public string Reserved, Desktop, Title;
        public uint X, Y, XSize, YSize, XChars, YChars, Fill, Flags;
        public ushort Show, ReservedSize;
        public IntPtr ReservedData, Input, Output, Error;
    }
    [StructLayout(LayoutKind.Sequential)]
    struct ProcessInfo { public IntPtr Process, Thread; public uint ProcessId, ThreadId; }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern IntPtr CreateJobObjectW(IntPtr security, string name);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool SetInformationJobObject(IntPtr job, int infoClass, ref ExtendedLimits info, uint size);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool AssignProcessToJobObject(IntPtr job, IntPtr process);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern bool CreateProcessW(string app, StringBuilder line, IntPtr processSecurity,
        IntPtr threadSecurity, bool inherit, uint flags, IntPtr environment, string cwd,
        ref StartupInfo startup, out ProcessInfo process);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern uint ResumeThread(IntPtr thread);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern uint WaitForSingleObject(IntPtr handle, uint milliseconds);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool GetExitCodeProcess(IntPtr process, out uint code);
    [DllImport("kernel32.dll")]
    static extern IntPtr GetStdHandle(int handle);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool TerminateProcess(IntPtr process, uint code);
    [DllImport("kernel32.dll")]
    static extern bool CloseHandle(IntPtr handle);

    static void Check(bool success) {
        if (!success) throw new Win32Exception(Marshal.GetLastWin32Error());
    }

    public static int Run(string commandLine) {
        IntPtr job = CreateJobObjectW(IntPtr.Zero, null);
        Check(job != IntPtr.Zero);
        ProcessInfo process = new ProcessInfo();
        bool assigned = false;
        try {
            ExtendedLimits limits = new ExtendedLimits();
            limits.Basic.Flags = 0x2000; // JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
            Check(SetInformationJobObject(job, 9, ref limits, (uint)Marshal.SizeOf(typeof(ExtendedLimits))));
            StartupInfo startup = new StartupInfo();
            startup.Size = (uint)Marshal.SizeOf(typeof(StartupInfo));
            startup.Flags = 0x100; // STARTF_USESTDHANDLES
            startup.Input = GetStdHandle(-10);
            startup.Output = GetStdHandle(-11);
            startup.Error = GetStdHandle(-12);
            Check(CreateProcessW(null, new StringBuilder(commandLine), IntPtr.Zero, IntPtr.Zero,
                true, 0x4, IntPtr.Zero, null, ref startup, out process)); // CREATE_SUSPENDED
            Check(AssignProcessToJobObject(job, process.Process));
            assigned = true;
            Check(ResumeThread(process.Thread) != UInt32.MaxValue);
            Check(WaitForSingleObject(process.Process, UInt32.MaxValue) != UInt32.MaxValue);
            uint code;
            Check(GetExitCodeProcess(process.Process, out code));
            return unchecked((int)code);
        } finally {
            // If assignment failed, the suspended launcher must also be reaped.
            if (!assigned && process.Process != IntPtr.Zero) TerminateProcess(process.Process, 1);
            CloseHandle(job);
            if (process.Thread != IntPtr.Zero) CloseHandle(process.Thread);
            if (process.Process != IntPtr.Zero) CloseHandle(process.Process);
        }
    }
}
`;
