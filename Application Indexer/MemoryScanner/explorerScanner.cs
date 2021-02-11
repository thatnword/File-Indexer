using ProcessHacker.Native.Api;
using ProcessHacker.Native.Objects;
using ProcessHacker.Native.Security;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace MemoryScanner {
    public class explorerScanner {

        static int allactions = 0, count = 0, totalstrings = 0, bytesRead = 0, minsize = 9;
        static bool unicode = true, isUnicode = false;
        static byte byte2 = 0, byte1 = 0;

        static List<string> memory = new List<string>();

        static Stopwatch sw = new Stopwatch();

        public static ProcessAccess MinProcessReadMemoryRights = ProcessAccess.VmRead;

        public static bool IsChar(byte b) { return (b >= 32 && b <= 126) || b == 10 || b == 13 || b == 9; }

        public static void startExplorerScan() {
            Console.CursorVisible = false;
            Console.WriteLine(" [#] Currently scanning Files! Please wait.");

            sw.Start();

            #region Set priority & get process handle - github.com/MrCreeper2010

            Process.GetCurrentProcess().PriorityClass = System.Diagnostics.ProcessPriorityClass.RealTime;

            new Thread(() => {
                while (true) {
                    foreach (ProcessThread processThread in Process.GetCurrentProcess().Threads)
                        if (processThread.ThreadState != System.Diagnostics.ThreadState.Terminated)
                            processThread.PriorityLevel = ThreadPriorityLevel.TimeCritical;
                    Thread.Sleep(1);
                }
            }).Start();

            ProcessHandle phandle = new ProcessHandle(Process.GetProcessesByName("explorer")[0].Id, ProcessAccess.QueryInformation | MinProcessReadMemoryRights);

            byte[] clean_string = Encoding.Unicode.GetBytes("\0");

            #endregion

            #region Scan Memory - github.com/MrCreeper2010

            phandle.EnumMemory((info) => {
                if (info.Protect == MemoryProtection.AccessDenied) return true;
                if (info.State != MemoryState.Commit) return true;

                byte[] data = new byte[info.RegionSize.ToInt32()];

                totalstrings += info.RegionSize.ToInt32();

                bytesRead = phandle.ReadMemory(info.BaseAddress, data, data.Length);

                StringBuilder curstr = new StringBuilder();

                for (int i = 0; i < bytesRead; i++) {
                    bool isChar = IsChar(data[i]);

                    if (unicode && isChar && isUnicode && byte1 > 0) {
                        isUnicode = false;

                        if (curstr.Length > 0) curstr.Remove(curstr.Length - 1, 1);

                        curstr.Append((char)data[i]);
                    } else if (isChar) curstr.Append((char)data[i]);
                    else if (unicode && data[i] == 0 && IsChar(byte1) && !IsChar(byte2)) isUnicode = true;
                    else if (unicode && data[i] == 0 && IsChar(byte1) && IsChar(byte2) && curstr.Length < minsize) {

                        isUnicode = true;

                        curstr = new StringBuilder();
                        curstr.Append((char)byte1);
                    } else {
                        if (curstr.Length >= minsize && curstr.Length <= 150) {
                            int length = curstr.Length;

                            if (isUnicode) length *= 2;
                            if (!curstr.ToString().Contains("	")) memory.Add(curstr.ToString());

                            allactions++;
                            count++;
                        }

                        isUnicode = false;
                        curstr = new StringBuilder();
                    }

                    byte2 = byte1;
                    byte1 = data[i];
                }
                data = null;

                return true;
            });
            phandle.Dispose();

            #endregion

            #region File checker - github.com/thatnword

            List<string> doesExist = new List<string>();
            List<string> doesntExist = new List<string>();

            foreach (string line in memory)
                if (line.Contains("file:///") && line.Contains(".exe") && !doesExist.Contains(line) && !doesntExist.Contains(line))
                    if (File.Exists(line.Replace("file:///", "").Replace("%20", " "))) doesExist.Add(line);
                    else doesntExist.Add(line);

            var fixedList1 = doesExist.Select(s => s.Replace("file:///", "").Replace("%20", " ")).ToList();
            var fixedList2 = doesntExist.Select(s => s.Replace("file:///", "").Replace("%20", " ")).ToList();

            var sortedValidFiles = fixedList1.OrderBy(x => x.Length);
            var sortedInvalidFiles = fixedList2.OrderBy(x => x.Length);

            /* list files that do exist */

            foreach (string line in sortedValidFiles)
                if (doesExist.Count == 0) writeAlert(ConsoleColor.DarkGray, "", "Unable to find any files");
                else writeAlert(ConsoleColor.Green, "Executed", line);

            /* list files that dont exist */

            Console.ForegroundColor = ConsoleColor.DarkGray;

            foreach (string line in sortedInvalidFiles)
                if (doesntExist.Count == 0) writeAlert(ConsoleColor.DarkGray, "", "Unable to find any files");
                else writeAlert(ConsoleColor.Red, "Deleted & Executed", line);

            #endregion

            #region Compile time checker - github.com/thatnword

            List<string> flaggedFiles = new List<string>();

            foreach (string line in sortedValidFiles)
                foreach (string detection in compileTimeChecker.detections)
                    if (compileTimeChecker.getCompileTime(line).Contains(detection) && !flaggedFiles.Contains(line))
                        flaggedFiles.Add(line);

            foreach (string item in flaggedFiles)
                writeAlert(ConsoleColor.Red, "Cheat file", item);

            #endregion

            Console.WriteLine($"  -  Finished scanning Files!");
            Console.WriteLine($"  -  The scan lasted {sw.ElapsedMilliseconds}ms");

            Console.ForegroundColor = ConsoleColor.Black;
        }

        static void writeAlert(ConsoleColor warningType, string type, string message) {
            Console.ForegroundColor = warningType;
            Console.Write("     " + type);
            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine(" - " + message);
        }
    }
}
