using System;
using System.ComponentModel;
using System.IO;
using System.Management.Automation;
using System.Management.Automation.Runspaces;
using System.IO.Pipes;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.ServiceProcess;
using System.Text.RegularExpressions;
using System.Threading;
using Microsoft.Win32.SafeHandles;

[assembly: AssemblyTitle("NorthGate Create-Only Service Host")]
[assembly: AssemblyDescription("Fixed Windows service host for the NorthGate create-only control plane")]
[assembly: AssemblyCompany("NorthGate Lab")]
[assembly: AssemblyProduct("NorthGate VM Factory")]
[assembly: AssemblyCopyright("Copyright NorthGate Lab")]
[assembly: ComVisible(false)]
[assembly: Guid("c898eb82-d9d9-4c11-a9f6-26e4886809c6")]
[assembly: AssemblyVersion("1.0.0.0")]
[assembly: AssemblyFileVersion("1.0.0.0")]

namespace NorthGate.VMFactory.CreateOnly
{
    public sealed class PipeClientIdentity
    {
        internal PipeClientIdentity(string sid, bool isAdministrator)
        {
            this.Sid = sid;
            this.IsAdministrator = isAdministrator;
        }

        public string Sid { get; private set; }
        public bool IsAdministrator { get; private set; }
    }

    public static class PipeClientIdentityCapture
    {
        public static PipeClientIdentity Capture(NamedPipeServerStream pipe)
        {
            if (pipe == null || !pipe.IsConnected)
            {
                throw new InvalidOperationException("NGCOR-PIPE-CLIENT-IDENTITY-UNAVAILABLE");
            }

            PipeClientIdentity captured = null;
            pipe.RunAsClient(delegate
            {
                using (WindowsIdentity identity = WindowsIdentity.GetCurrent(true))
                {
                    if (identity == null || identity.User == null)
                    {
                        throw new InvalidOperationException("NGCOR-PIPE-CLIENT-IDENTITY-UNAVAILABLE");
                    }
                    WindowsPrincipal principal = new WindowsPrincipal(identity);
                    captured = new PipeClientIdentity(
                        identity.User.Value,
                        principal.IsInRole(WindowsBuiltInRole.Administrator));
                }
            });

            if (captured == null)
            {
                throw new InvalidOperationException("NGCOR-PIPE-CLIENT-IDENTITY-UNAVAILABLE");
            }
            return captured;
        }
    }

    public static class PipeServerIdentityVerifier
    {
        private const uint ScManagerConnect = 0x0001;
        private const uint ServiceQueryStatus = 0x0004;
        private const uint ServiceRunning = 0x00000004;

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool GetNamedPipeServerProcessId(
            SafePipeHandle pipe,
            out uint serverProcessId);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr OpenSCManager(
            string machineName,
            string databaseName,
            uint desiredAccess);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr OpenService(
            IntPtr manager,
            string serviceName,
            uint desiredAccess);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool QueryServiceStatusEx(
            IntPtr service,
            int infoLevel,
            out ServiceStatusProcess status,
            int bufferSize,
            out int bytesNeeded);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool CloseServiceHandle(IntPtr handle);

        [StructLayout(LayoutKind.Sequential)]
        private struct ServiceStatusProcess
        {
            public uint ServiceType;
            public uint CurrentState;
            public uint ControlsAccepted;
            public uint Win32ExitCode;
            public uint ServiceSpecificExitCode;
            public uint CheckPoint;
            public uint WaitHint;
            public uint ProcessId;
            public uint ServiceFlags;
        }

        public static uint GetPipeServerProcessId(SafePipeHandle pipe)
        {
            if (pipe == null || pipe.IsInvalid || pipe.IsClosed)
            {
                throw new InvalidOperationException("NGCOR-PIPE-SERVER-HANDLE-INVALID");
            }
            uint processId;
            if (!GetNamedPipeServerProcessId(pipe, out processId) || processId == 0)
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }
            return processId;
        }

        public static uint GetServiceProcessId(string serviceName)
        {
            if (String.IsNullOrEmpty(serviceName))
            {
                throw new InvalidOperationException("NGCOR-PIPE-SERVER-SERVICE-NAME-INVALID");
            }
            IntPtr manager = OpenSCManager(null, null, ScManagerConnect);
            if (manager == IntPtr.Zero)
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }
            try
            {
                IntPtr service = OpenService(manager, serviceName, ServiceQueryStatus);
                if (service == IntPtr.Zero)
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                }
                try
                {
                    ServiceStatusProcess status;
                    int bytesNeeded;
                    int size = Marshal.SizeOf(typeof(ServiceStatusProcess));
                    if (!QueryServiceStatusEx(service, 0, out status, size, out bytesNeeded))
                    {
                        throw new Win32Exception(Marshal.GetLastWin32Error());
                    }
                    if (status.CurrentState != ServiceRunning || status.ProcessId == 0)
                    {
                        throw new InvalidOperationException("NGCOR-PIPE-SERVER-SERVICE-NOT-RUNNING");
                    }
                    return status.ProcessId;
                }
                finally
                {
                    CloseServiceHandle(service);
                }
            }
            finally
            {
                CloseServiceHandle(manager);
            }
        }
    }

    internal static class Program
    {
        private const string ScriptSwitch = "--script";
        private const string ScriptFileName = "Start-NorthGateCreateOnlyPipeService.ps1";

        private static int Main(string[] args)
        {
            try
            {
                string scriptPath = ValidateCommandLine(args);
                ServiceBase.Run(new ServiceBase[] { new CreateOnlyService(scriptPath) });
                return 0;
            }
            catch
            {
                return 64;
            }
        }

        private static string ValidateCommandLine(string[] args)
        {
            if (args == null || args.Length != 2 ||
                !string.Equals(args[0], ScriptSwitch, StringComparison.Ordinal))
            {
                throw new InvalidOperationException("NGCOR-SERVICE-HOST-ARGUMENTS-INVALID");
            }

            string executablePath = Path.GetFullPath(Assembly.GetExecutingAssembly().Location);
            string executableRoot = Path.GetDirectoryName(executablePath);
            if (string.IsNullOrEmpty(executableRoot))
            {
                throw new InvalidOperationException("NGCOR-SERVICE-HOST-LOCATION-INVALID");
            }

            string expectedScriptPath = Path.GetFullPath(Path.Combine(executableRoot, ScriptFileName));
            string suppliedScriptPath = Path.GetFullPath(args[1]);
            if (!string.Equals(suppliedScriptPath, expectedScriptPath, StringComparison.OrdinalIgnoreCase) ||
                !File.Exists(suppliedScriptPath))
            {
                throw new InvalidOperationException("NGCOR-SERVICE-HOST-SCRIPT-INVALID");
            }

            AssertNoReparsePath(executablePath);
            AssertNoReparsePath(suppliedScriptPath);
            return suppliedScriptPath;
        }

        private static void AssertNoReparsePath(string path)
        {
            string current = Path.GetFullPath(path);
            while (!string.IsNullOrEmpty(current))
            {
                if (!File.Exists(current) && !Directory.Exists(current))
                {
                    throw new InvalidOperationException("NGCOR-SERVICE-HOST-PATH-INVALID");
                }
                if ((File.GetAttributes(current) & FileAttributes.ReparsePoint) != 0)
                {
                    throw new InvalidOperationException("NGCOR-SERVICE-HOST-REPARSE-FORBIDDEN");
                }
                DirectoryInfo parent = Directory.GetParent(current);
                if (parent == null || string.Equals(parent.FullName, current, StringComparison.OrdinalIgnoreCase))
                {
                    break;
                }
                current = parent.FullName;
            }
        }
    }

    internal sealed class CreateOnlyService : ServiceBase
    {
        private const string FixedServiceName = "NorthGateCreateOnly";
        private readonly string scriptPath;
        private readonly ManualResetEvent stopEvent;
        private readonly object engineGate;
        private Thread worker;
        private PowerShell engine;
        private volatile bool stopping;

        internal CreateOnlyService(string scriptPath)
        {
            this.scriptPath = scriptPath;
            this.stopEvent = new ManualResetEvent(false);
            this.engineGate = new object();
            this.ServiceName = FixedServiceName;
            this.AutoLog = false;
            this.CanStop = true;
            this.CanShutdown = true;
            this.CanPauseAndContinue = false;
        }

        protected override void OnStart(string[] args)
        {
            if (args != null && args.Length != 0)
            {
                throw new InvalidOperationException("NGCOR-SERVICE-START-ARGUMENTS-FORBIDDEN");
            }
            if (this.worker != null)
            {
                throw new InvalidOperationException("NGCOR-SERVICE-ALREADY-STARTED");
            }

            this.stopping = false;
            this.stopEvent.Reset();
            this.worker = new Thread(this.RunEngine);
            this.worker.IsBackground = true;
            this.worker.Name = "NorthGateCreateOnlyEngine";
            this.worker.Start();
        }

        protected override void OnStop()
        {
            StopEngine();
        }

        protected override void OnShutdown()
        {
            StopEngine();
            base.OnShutdown();
        }

        private void StopEngine()
        {
            this.stopping = true;
            this.stopEvent.Set();
            Thread workerSnapshot = this.worker;
            if (workerSnapshot == null)
            {
                return;
            }

            this.RequestAdditionalTime(20000);
            if (!workerSnapshot.Join(15000))
            {
                PowerShell engineSnapshot;
                lock (this.engineGate)
                {
                    engineSnapshot = this.engine;
                }
                if (engineSnapshot != null)
                {
                    try { engineSnapshot.Stop(); }
                    catch { }
                }
                if (!workerSnapshot.Join(5000))
                {
                    Environment.FailFast("NorthGate create-only service could not stop safely.");
                }
            }
            this.worker = null;
        }

        private void RunEngine()
        {
            try
            {
                using (Runspace runspace = RunspaceFactory.CreateRunspace())
                {
                    runspace.ApartmentState = ApartmentState.MTA;
                    runspace.ThreadOptions = PSThreadOptions.UseCurrentThread;
                    runspace.Open();
                    runspace.SessionStateProxy.SetVariable("NorthGateServiceStopEvent", this.stopEvent);

                    using (PowerShell localEngine = PowerShell.Create())
                    {
                        localEngine.Runspace = runspace;
                        lock (this.engineGate)
                        {
                            this.engine = localEngine;
                        }
                        localEngine.AddCommand(this.scriptPath);
                        localEngine.Invoke();
                        if (!this.stopping && localEngine.HadErrors)
                        {
                            Exception failure = localEngine.Streams.Error.Count == 0
                                ? null
                                : localEngine.Streams.Error[0].Exception;
                            Environment.FailFast(
                                "NorthGate create-only service engine failed. Code=" + GetSafeFailureCode(failure));
                        }
                    }
                }
                if (!this.stopping)
                {
                    Environment.FailFast("NorthGate create-only service engine exited unexpectedly.");
                }
            }
            catch (Exception exception)
            {
                if (!this.stopping)
                {
                    Environment.FailFast(
                        "NorthGate create-only service engine failed unexpectedly. Code=" +
                        GetSafeFailureCode(exception));
                }
            }
            finally
            {
                lock (this.engineGate)
                {
                    this.engine = null;
                }
            }
        }

        private static string GetSafeFailureCode(Exception exception)
        {
            if (exception == null)
            {
                return "unknown";
            }
            Match match = Regex.Match(
                exception.Message ?? String.Empty,
                @"\bNGCOR-[A-Z0-9-]{1,96}\b",
                RegexOptions.CultureInvariant);
            return match.Success ? match.Value : exception.GetType().FullName;
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                this.stopEvent.Dispose();
            }
            base.Dispose(disposing);
        }
    }
}
