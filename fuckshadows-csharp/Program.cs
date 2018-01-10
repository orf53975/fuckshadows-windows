using System;
using System.Diagnostics;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;
using Fuckshadows.Controller;
using Fuckshadows.Controller.Hotkeys;
using Fuckshadows.Util;
using Fuckshadows.View;
using Microsoft.Win32;

namespace Fuckshadows
{
    static class Program
    {
        public static FuckshadowsController MainController { get; private set; }
        public static MenuViewController MenuController { get; private set; }
        public static bool TFOSupported { get; private set; }

        /// <summary>
        /// 应用程序的主入口点。
        /// </summary>
        [STAThread]
        static void Main()
        {
            TFOSupported = Utils.IsTcpFastOpenSupported();

            using (Mutex mutex = new Mutex(false, $"Global\\Fuckshadows_{Application.StartupPath.GetHashCode()}"))
            {
                Application.SetUnhandledExceptionMode(UnhandledExceptionMode.CatchException);
                // handle UI exceptions
                Application.ThreadException += Application_ThreadException;
                // handle non-UI exceptions
                AppDomain.CurrentDomain.UnhandledException += CurrentDomain_UnhandledException;
                // handle unobserved Task exceptions
                TaskScheduler.UnobservedTaskException += TaskScheduler_UnobservedTaskException;
                Application.ApplicationExit += Application_ApplicationExit;
                Application.EnableVisualStyles();
                Application.SetCompatibleTextRenderingDefault(false);

                if (!mutex.WaitOne(0, false))
                {
                    Process[] oldProcesses = Process.GetProcessesByName("Fuckshadows");
                    if (oldProcesses.Length > 0)
                    {
                        Process oldProcess = oldProcesses[0];
                    }
                    MessageBox.Show(I18N.GetString("Find Fuckshadows icon in your notify tray.")
                                    + Environment.NewLine
                                    +
                                    I18N.GetString(
                                        "If you want to start multiple Fuckshadows, make a copy in another directory."),
                        I18N.GetString("Fuckshadows is already running."));
                    return;
                }
                Directory.SetCurrentDirectory(Application.StartupPath);
#if DEBUG
                Logging.OpenLogFile();

                // truncate privoxy log file while debugging
                string privoxyLogFilename = Utils.GetTempPath("privoxy.log");
                if (File.Exists(privoxyLogFilename))
                    using (new FileStream(privoxyLogFilename, FileMode.Truncate))
                    {
                    }
#else
                Logging.OpenLogFile();
#endif
                // setup profile optimization
                System.Runtime.ProfileOptimization.SetProfileRoot(Utils.GetTempPath());
                System.Runtime.ProfileOptimization.StartProfile("fuckshadows-opt-profile");

                MainController = new FuckshadowsController();
                MenuController = new MenuViewController(MainController);
                HotKeys.Init(MainController);
                MainController.Start();
                Application.Run();
            }
        }

        private static int exited = 0;

        private static void CurrentDomain_UnhandledException(object sender, UnhandledExceptionEventArgs e)
        {
            if (Interlocked.Increment(ref exited) == 1)
            {
                string errMsg = e.ExceptionObject.ToString();
                Logging.Error(errMsg);
                MessageBox.Show(
                    $"{I18N.GetString("Unexpected error, fuckshadows will exit. Please report to")} https://github.com/Fuckshadows/Fuckshadows-windows/issues {Environment.NewLine}{errMsg}",
                    "Fuckshadows non-UI Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                Application.Exit();
            }
        }

        private static void Application_ThreadException(object sender, ThreadExceptionEventArgs e)
        {
            if (Interlocked.Increment(ref exited) == 1)
            {
                string errorMsg = $"Exception Detail: {Environment.NewLine}{e.Exception}";
                Logging.Error(errorMsg);
                MessageBox.Show(
                    $"{I18N.GetString("Unexpected error, fuckshadows will exit. Please report to")} https://github.com/Fuckshadows/Fuckshadows-windows/issues {Environment.NewLine}{errorMsg}",
                    "Fuckshadows UI Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                Application.Exit();
            }
        }

        private static void TaskScheduler_UnobservedTaskException(object sender, UnobservedTaskExceptionEventArgs e)
        {
            if (Interlocked.Increment(ref exited) == 1)
            {
                var exps = e.Exception.InnerExceptions;
                string errMsg = String.Empty;
                foreach (var exp in exps)
                {
                    errMsg += exp.ToString();
                }
                Logging.Error(errMsg);
                MessageBox.Show(
                                $"{I18N.GetString("Unexpected error, fuckshadows will exit. Please report to")} https://github.com/Fuckshadows/Fuckshadows-windows/issues {Environment.NewLine}{errMsg}",
                                "Fuckshadows Task Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                Application.Exit();
            }
        }

        private static void Application_ApplicationExit(object sender, EventArgs e)
        {
            // detach static event handlers
            Application.ApplicationExit -= Application_ApplicationExit;
            Application.ThreadException -= Application_ThreadException;
            TaskScheduler.UnobservedTaskException -= TaskScheduler_UnobservedTaskException;
            HotKeys.Destroy();
            if (MainController != null)
            {
                MainController.Stop();
                MainController = null;
            }
        }

        public static void DisableTFO() { TFOSupported = false; }
    }
}