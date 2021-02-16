#region Includes
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Runtime.InteropServices;
using System.Diagnostics;
using System.Threading;
using System.Windows.Forms;
using System.Reflection;
using System.Security.Cryptography;
using System.IO;
using System.Runtime.Serialization.Formatters.Binary;
using System.Reflection.Emit;
#endregion


/*
Protection based off: https://github.com/lhaasper/C-Single-Header-Protection-Windows-customizable/, https://www.unknowncheats.me/forum/c-and-c-/439421-anticrack-protection-header-single-header-noob-friendly-customizable.html
(By based off i mean i got inspired to do something like it in c# and i used some of the strings)

Decent Native .Net Protection:

Features:
Injection Detection: Detects dlls being injected.
Runtime Process Checker: Checks for reverse engineering / malicious process during runtime and exits if theyre found.
Runtime Anti Debug Protection: Uses IsDebuggerPresent to check if a debugger is attached. (Pretty shit method)
Runtime Load Assembly: Loads an assembly from bytes, basically makes it take like 5 minutes longer to crack if you have antidump.
Kill Debugger Protection: Executes killdebuglist strings to attempt to kill debuggers.
Encryption: encrypts and decrypts strings.


Code Features:
Commented kinda
Bad code if you know what your doing, good code if youre new to coding.

Notes:
this is made for beginners so dont expect the best code.
Also im very tired right now.

Also this protection doesnt help much if you dont obfuscate or virtualize ur shit.
 
 */

namespace Security
{
    class protection
    {
        #region vars
        //user changeable
        public bool RuntimeProcessCheckerProtection = false;
        public bool RuntimeAntiDebugProtection = false;
        public bool KillDebuggerProtection = false;
        public bool KillMaliciousProcess = false;
        public bool DetectDllInjection = false;
        public bool RunSingleThread = false;
        public bool ShowDebug = false;//idk maybe u wanna view debug shit while compiling as release?


        private const int moduleCount = 124;
        private const string EncryptionHash = "dheuihiauhsdkjhafujkiahuiodhsjkfhuorsjsoaifioprwugilhsuiogfhoahdfjuophgoiaerw";//change if u want
        private bool beenInitialized = false;
        private static readonly string[] badPList = { "KsDumperClient", "HTTPDebuggerUI", "FolderChangesView", "ProcessHacker", "procmon", "idaq", "idaq64", "Wireshark", "Fiddler", "Xenos64", "Cheat Engine", "HTTP Debugger Windows Service (32 bit)", "KsDumper", "x64dbg", "x32dbg", "dnspy", "dnspy(x86)" };//u can add shit here.
        private static readonly string[] killDebugList = { "taskkill /f /im HTTPDebuggerUI.exe >nul 2>&1", "taskkill /f /im HTTPDebuggerSvc.exe >nul 2>&1", "sc stop HTTPDebuggerPro >nul 2>&1", "taskkill /FI \"IMAGENAME eq cheatengine*\" /IM * /F /T >nul 2>&1", "taskkill /FI \"IMAGENAME eq httpdebugger*\" /IM * /F /T >nul 2>&1", "taskkill /FI \"IMAGENAME eq processhacker*\" /IM * /F /T >nul 2>&1", "taskkill /FI \"IMAGENAME eq fiddler*\" /IM * /F /T >nul 2>&1", "taskkill /FI \"IMAGENAME eq wireshark*\" /IM * /F /T >nul 2>&1", "taskkill /FI \"IMAGENAME eq rawshark*\" /IM * /F /T >nul 2>&1", "taskkill /FI \"IMAGENAME eq charles*\" /IM * /F /T >nul 2>&1", "taskkill /FI \"IMAGENAME eq cheatengine*\" /IM * /F /T >nul 2>&1", "taskkill /FI \"IMAGENAME eq ida*\" /IM * /F /T >nul 2>&1", "taskkill /FI \"IMAGENAME eq httpdebugger*\" /IM * /F /T >nul 2>&1", "taskkill /FI \"IMAGENAME eq processhacker*\" /IM * /F /T >nul 2>&1", "sc stop HTTPDebuggerPro >nul 2>&1", "sc stop KProcessHacker3 >nul 2>&1", "sc stop KProcessHacker2 >nul 2>&1", "sc stop KProcessHacker1 >nul 2>&1", "sc stop wireshark >nul 2>&1", "sc stop npf >nul 2>&1", };// again u can add shit here
        #endregion
        public protection()
        {

        }
        public void initialize()//inits protections.
        {
            if (ShowDebug) Console.WriteLine("[+] Initializing Protections. \n");
            if (!beenInitialized)
            {// I couldve made each of these their own method but its easier to have an initialize method. i think...
                if (RunSingleThread)
                {
                    if (ShowDebug) Console.WriteLine("[+] Initializing Single Thread.");
                    Thread single = new Thread(singleThd);
                    single.Start();
                }
                else
                {
                    if (RuntimeProcessCheckerProtection)
                    {
                        if (ShowDebug) Console.WriteLine("[+] Initializing Process Checker.");
                        Thread procThread = new Thread(maliciousProcessChecker);
                        procThread.Start();
                    }
                    if (RuntimeAntiDebugProtection)
                    {
                        if (ShowDebug) Console.WriteLine("[+] Initializing Anti Debug.");
                        Thread dbgThread = new Thread(antiDebugThread);
                        dbgThread.Start();
                    }
                    if (DetectDllInjection)
                    {
                        if (ShowDebug) Console.WriteLine("[+] Initializing Inject Detection.");
                        Thread detinjThd = new Thread(injectDetectThread);
                        detinjThd.Start();
                    }
                    if (KillDebuggerProtection)
                    {
                        if (ShowDebug) Console.WriteLine("[+] Killing Debuggers");
                        killDebuggers();
                    }
                    beenInitialized = true;
                }
            }
            else
            {
                return;
                //MessageBox.Show("This application has been set up incorrectly: the protection has been intialized twice.", "Blankets Runtime Protector:", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }
        #region Single Thread
        private void singleThd()//this should be better for optimization. should be.
        {
            if (ShowDebug) Console.WriteLine("[+] Thread Initialized.");
            if (RunSingleThread)
            {
                while (true)
                {
                    if (RuntimeAntiDebugProtection)
                    {
                        sngldetectDebug();
                    }
                    Thread.Sleep(25);
                    if (RuntimeProcessCheckerProtection)
                    {
                        snglMalProc();
                    }
                    Thread.Sleep(25);
                    if (DetectDllInjection)
                    {
                        if (detectModules())
                        {
                            loadDummy();
                        }
                    }
                    Thread.Sleep(100);
                }

            }
            else
            {
                return;
            }
        }

        #endregion
        #region Anti Debugging
        private void antiDebugThread()
        {
            while (true)
            {
                if (IsDebuggerPresent())
                {

                    //obviously you dont want to anti debug when youre debugging :/
#if DEBUG
                    goto skip;
#endif
                    Environment.Exit(-1);
                }
            skip:
                Thread.Sleep(50);
            }

        }
        //SingleThread:
        //u might say this is bad code but youd be very wrong. allow me to explain: youre very wrong.
        //basically its better to have 2 seperate methods than do an if else as someone could could type 1 ! and bypass the antidebug.
        private void sngldetectDebug()
        {
            if (IsDebuggerPresent())
            {
                //obviously you dont want to anti debug when youre debugging :/
#if DEBUG
                return;
#endif
                Environment.Exit(-1);
            }

        }

        #endregion
        #region Process Scanner
        private void maliciousProcessChecker()//Checker Thread
        {
            while (true)
            {
                foreach (string str in badPList)//for every string in the array... :/
                {
                    if (isProcess(str))//if its running exit....
                    {
                        if (ShowDebug) Console.WriteLine("Bad Process Found: " + str);
                        Environment.Exit(-1);
                    }
                    Thread.Sleep(10);
                }
                Thread.Sleep(20);
            }
        }
        //Checker Helper:
        private bool isProcess(string pname)//checks if process is running.
        {
            bool pRunning = Process.GetProcessesByName(pname).Any();
            if (pRunning)
            {
                Process p = Process.GetProcessesByName(pname).FirstOrDefault();
                if (KillMaliciousProcess)
                {
                    try//throws exception if not running as admin
                    {
                        p.Kill();//while we could do in the malprocchecker func its safer to do it here... i think.
                    }
                    catch
                    {
                    }
                }
            }
            return pRunning;
        }
        //single thread method as if i did an if statement all youd have to do to disable it would be type a single !.
        private void snglMalProc()
        {
            foreach (string str in badPList)
            {
                if (isProcess(str))//if its running exit....
                {
                    Environment.Exit(-1);
                }
                Thread.Sleep(10);
            }
            Thread.Sleep(20);
        }
        #endregion
        #region Other Protections
        //Kill debuggers (or at least thats what the guy calls it?(that guy being the guy from the uc thread at the top.)):
        private void killDebuggers()
        {
            foreach (string str in killDebugList)
            {
                try//throws exceptions if it isnt running.
                {
                    Process.Start(str);
                    if (ShowDebug) Console.WriteLine("Debugger Killed");
                }
                catch
                {

                }
            }
        }
        public void runtimeLoadAsm(byte[] fBytes)
        {
            //File Bytes can be aquired by using file.readallbytes and converted to a string by Convert.ToBase64String(bytes) the converted back via Convert.FromBase64String.
            if (beenInitialized)//can only call after being initialized
            {
                Assembly asm = Assembly.Load(fBytes);
                var entryPoint = asm.EntryPoint;
                string[] args = { "", }; //if the desired assembly to load requires arguments put them here.
                asm.EntryPoint.Invoke(null, new object[] { args });
            }
            else
            {
                MessageBox.Show("Error: Application is set up incorrect. You must initialize protection before calling methods.", "Blankets .net Protector", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }
        #endregion
        #region Encryption
        //i dont like aes... fuck aes... more like awful encryption standard ahah im halarious 
        //pasted off stack overflow...
        public string Encrypt(string text)
        {
            if (beenInitialized)
            {
                using (var md5 = new MD5CryptoServiceProvider())
                {
                    using (var tdes = new TripleDESCryptoServiceProvider())
                    {
                        tdes.Key = md5.ComputeHash(UTF8Encoding.UTF8.GetBytes(EncryptionHash));
                        tdes.Mode = CipherMode.ECB;
                        tdes.Padding = PaddingMode.PKCS7;

                        using (var transform = tdes.CreateEncryptor())
                        {
                            byte[] textBytes = UTF8Encoding.UTF8.GetBytes(text);
                            byte[] bytes = transform.TransformFinalBlock(textBytes, 0, textBytes.Length);
                            return Convert.ToBase64String(bytes, 0, bytes.Length);
                        }
                    }
                }
            }
            else
            {
                MessageBox.Show("Error: Application is set up incorrect. You must initialize protection before calling methods.", "Blankets .net Protector", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return "";
            }
        }
        public string Decrypt(string text)
        {
            if (beenInitialized)
            {
                using (var md5 = new MD5CryptoServiceProvider())
                {
                    using (var tdes = new TripleDESCryptoServiceProvider())
                    {
                        tdes.Key = md5.ComputeHash(UTF8Encoding.UTF8.GetBytes(EncryptionHash));
                        tdes.Mode = CipherMode.ECB;
                        tdes.Padding = PaddingMode.PKCS7;

                        using (var transform = tdes.CreateDecryptor())
                        {
                            byte[] cipherBytes = Convert.FromBase64String(text);
                            byte[] bytes = transform.TransformFinalBlock(cipherBytes, 0, cipherBytes.Length);
                            return UTF8Encoding.UTF8.GetString(bytes);
                        }
                    }
                }
            }
            else
            {
                MessageBox.Show("Error: Application is set up incorrect. You must initialize protection before calling methods.", "Blankets .net Protector", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return "";
            }
        }
        #endregion
        #region inject Detection
        private void injectDetectThread()
        {
            int lol = Console.CursorTop;
            while (true)
            {
                Thread.Sleep(150);
                if (detectModules())
                {
                    //Console.WriteLine(@"[-] Nothing Detected");
                    //Console.SetCursorPosition(0, lol);
                }
                else
                {
                    Environment.Exit(-1);
                    //Console.WriteLine("[+] Dll Injection Detected");
                    //Console.SetCursorPosition(0, lol);
                }
                Thread.Sleep(150);
            }
        }
        //https://docs.microsoft.com/en-us/windows/win32/psapi/enumerating-all-modules-for-a-process
        public bool detectModules()
        {
            Process proc = Process.GetCurrentProcess();
            int total = 0;
            if (!EnumProcessModulesEx(proc.Handle, new IntPtr[] { IntPtr.Zero }, 0, out total, (uint)0x03))
            {
                return true;
            }
            if (total != moduleCount)
            {
                return false;
            }
            else
            {
                return true;
            }
        }
        #endregion
        #region MiscStuff

        private void loadDummy()//loads dummy. pretty much just so you can call whoever tried to crack ur software a fag.
        {
            //this is kinda shit tbh just start cmd with echo ur gay
            string bts = "TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgAAAAA4fug4AtAnNIbgBTM0hVGhpcyBwcm9ncmFtIGNhbm5vdCBiZSBydW4gaW4gRE9TIG1vZGUuDQ0KJAAAAAAAAABQRQAATAEDAKD0SMYAAAAAAAAAAOAAIgALATAAAAgAAAAIAAAAAAAANicAAAAgAAAAQAAAAABAAAAgAAAAAgAABAAAAAAAAAAGAAAAAAAAAACAAAAAAgAAAAAAAAMAYIUAABAAABAAAAAAEAAAEAAAAAAAABAAAAAAAAAAAAAAAOMmAABPAAAAAEAAAKwFAAAAAAAAAAAAAAAAAAAAAAAAAGAAAAwAAABEJgAAOAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIAAACAAAAAAAAAAAAAAACCAAAEgAAAAAAAAAAAAAAC50ZXh0AAAAPAcAAAAgAAAACAAAAAIAAAAAAAAAAAAAAAAAACAAAGAucnNyYwAAAKwFAAAAQAAAAAYAAAAKAAAAAAAAAAAAAAAAAABAAABALnJlbG9jAAAMAAAAAGAAAAACAAAAEAAAAAAAAAAAAAAAAAAAQAAAQgAAAAAAAAAAAAAAAAAAAAAXJwAAAAAAAEgAAAACAAUAcCAAANQFAAADAAIAAQAABgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE4AcgEAAHAoDwAACgAoEAAACiYqIgIoEQAACgAqAAAAQlNKQgEAAQAAAAAADAAAAHY0LjAuMzAzMTkAAAAABQBsAAAA0AEAACN+AAA8AgAAaAIAACNTdHJpbmdzAAAAAKQEAAAIAAAAI1VTAKwEAAAQAAAAI0dVSUQAAAC8BAAAGAEAACNCbG9iAAAAAAAAAAIAAAFHFQAACQAAAAD6ATMAFgAAAQAAABEAAAACAAAAAgAAAAEAAAARAAAADgAAAAEAAAABAAAAAACTAQEAAAAAAAYACAEtAgYAdQEtAgYAPAD7AQ8ATQIAAAYAZADPAQYA6wDPAQYAzADPAQYAXAHPAQYAKAHPAQYAQQHPAQYAewDPAQYAUAAOAgYALgAOAgYArwDPAQYAlgChAQYAYQLDAQYAEwDDAQAAAAABAAAAAAABAAEAAAAQALsB6wFBAAEAAQBQIAAAAACRAMoBLAABAGQgAAAAAIYY9QEGAAIAAAABAFwCCQD1AQEAEQD1AQYAGQD1AQoAKQD1ARAAMQD1ARAAOQD1ARAAQQD1ARAASQD1ARAAUQD1ARAAWQD1ARAAYQD1ARUAaQD1ARAAcQD1ARAAeQD1ARAAiQAkABoAiQAbAB8AgQD1AQYALgALADIALgATADsALgAbAFoALgAjAGMALgArAHIALgAzAHIALgA7AHIALgBDAGMALgBLAHgALgBTAHIALgBbAHIALgBjAJAALgBrALoALgBzAMcABIAAAAEAAAAAAAAAAAAAAAAA4QEAAAQAAAAAAAAAAAAAACMACgAAAAAAAAAAPE1vZHVsZT4AbXNjb3JsaWIAQ29uc29sZQBSZWFkTGluZQBXcml0ZUxpbmUAR3VpZEF0dHJpYnV0ZQBEZWJ1Z2dhYmxlQXR0cmlidXRlAENvbVZpc2libGVBdHRyaWJ1dGUAQXNzZW1ibHlUaXRsZUF0dHJpYnV0ZQBBc3NlbWJseVRyYWRlbWFya0F0dHJpYnV0ZQBUYXJnZXRGcmFtZXdvcmtBdHRyaWJ1dGUAQXNzZW1ibHlGaWxlVmVyc2lvbkF0dHJpYnV0ZQBBc3NlbWJseUNvbmZpZ3VyYXRpb25BdHRyaWJ1dGUAQXNzZW1ibHlEZXNjcmlwdGlvbkF0dHJpYnV0ZQBDb21waWxhdGlvblJlbGF4YXRpb25zQXR0cmlidXRlAEFzc2VtYmx5UHJvZHVjdEF0dHJpYnV0ZQBBc3NlbWJseUNvcHlyaWdodEF0dHJpYnV0ZQBBc3NlbWJseUNvbXBhbnlBdHRyaWJ1dGUAUnVudGltZUNvbXBhdGliaWxpdHlBdHRyaWJ1dGUAQmxhbmsgYXBwLmV4ZQBTeXN0ZW0uUnVudGltZS5WZXJzaW9uaW5nAFByb2dyYW0AU3lzdGVtAE1haW4AU3lzdGVtLlJlZmxlY3Rpb24AQmxhbmsgYXBwAEJsYW5rX2FwcAAuY3RvcgBTeXN0ZW0uRGlhZ25vc3RpY3MAU3lzdGVtLlJ1bnRpbWUuSW50ZXJvcFNlcnZpY2VzAFN5c3RlbS5SdW50aW1lLkNvbXBpbGVyU2VydmljZXMARGVidWdnaW5nTW9kZXMA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";
            runtimeLoadAsm(Convert.FromBase64String(bts));
        }

        #endregion
        #region Imports
        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool IsDebuggerPresent();
        [DllImport("psapi.dll")]
        public static extern bool EnumProcessModulesEx(IntPtr hProcess, [MarshalAs(UnmanagedType.LPArray, ArraySubType = UnmanagedType.U4)][In][Out] IntPtr[] lphModule, int cb, [MarshalAs(UnmanagedType.U4)] out int lpcbNeeded, uint dwFilterFlag);
        #endregion
    }
}
