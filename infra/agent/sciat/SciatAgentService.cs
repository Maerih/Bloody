// SCIAT Agent Windows service host — proprietary, (c) SCIAT AFRICA.
// Compiled on the endpoint at install time with the .NET Framework compiler (csc.exe) into
// "C:\Program Files\SCIAT\Agent\SCIATAgent.exe", registered as the "SCIAT Agent" service.
// It keeps sciat-agent.ps1 running and stops it with the service.
using System;
using System.Diagnostics;
using System.IO;
using System.ServiceProcess;
using System.Threading;

namespace Sciat.Agent
{
    public sealed class SciatAgentService : ServiceBase
    {
        private Process child;
        private Thread supervisor;
        private volatile bool stopping;

        public SciatAgentService()
        {
            ServiceName = "SCIATAgent";
            CanStop = true;
            CanShutdown = true;
            AutoLog = true;
        }

        private static string Home
        {
            get { return Path.GetDirectoryName(typeof(SciatAgentService).Assembly.Location); }
        }

        protected override void OnStart(string[] args)
        {
            stopping = false;
            supervisor = new Thread(Supervise) { IsBackground = true, Name = "sciat-supervisor" };
            supervisor.Start();
        }

        private void Supervise()
        {
            int failures = 0;
            while (!stopping)
            {
                try
                {
                    var psi = new ProcessStartInfo
                    {
                        FileName = Path.Combine(Environment.SystemDirectory, @"WindowsPowerShell\v1.0\powershell.exe"),
                        Arguments = "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File \"" + Path.Combine(Home, "sciat-agent.ps1") + "\" run",
                        UseShellExecute = false,
                        CreateNoWindow = true,
                        WorkingDirectory = Home,
                    };
                    child = Process.Start(psi);
                    child.WaitForExit();
                    failures = child.ExitCode == 0 ? 0 : failures + 1;
                }
                catch (Exception e)
                {
                    failures++;
                    try { EventLog.WriteEntry("SCIAT Agent", "agent process failed: " + e.Message, EventLogEntryType.Warning); } catch { }
                }
                // Restart the agent loop with a growing pause (max 5 minutes).
                for (int i = 0; i < Math.Min(15 * Math.Max(failures, 1), 300) && !stopping; i++) Thread.Sleep(1000);
            }
        }

        protected override void OnStop()
        {
            stopping = true;
            try { if (child != null && !child.HasExited) child.Kill(); } catch { }
            if (supervisor != null) supervisor.Join(5000);
        }

        protected override void OnShutdown() { OnStop(); }

        public static void Main()
        {
            ServiceBase.Run(new SciatAgentService());
        }
    }
}
