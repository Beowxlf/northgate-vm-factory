using System;
using System.IO;
using System.Management.Automation;
using System.Management.Automation.Runspaces;
using System.Reflection;
using System.Runtime.InteropServices;
using System.ServiceProcess;
using System.Threading;

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
                            Environment.FailFast("NorthGate create-only service engine failed.");
                        }
                    }
                }
                if (!this.stopping)
                {
                    Environment.FailFast("NorthGate create-only service engine exited unexpectedly.");
                }
            }
            catch
            {
                if (!this.stopping)
                {
                    Environment.FailFast("NorthGate create-only service engine failed unexpectedly.");
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
