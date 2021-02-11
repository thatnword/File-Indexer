using ProcessHacker.Native.Api;
using ProcessHacker.Native.Objects;
using ProcessHacker.Native.Security;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Text;
using System.Threading;


namespace MemoryScanner
{
    class Program
    {
        static void Main() {

            Console.Title = "Screenshare Tool - @xuiyxd";

            explorerScanner.startExplorerScan();

            Console.ReadLine();
        }
    }
}
