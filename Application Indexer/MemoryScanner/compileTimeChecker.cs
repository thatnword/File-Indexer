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
    public class compileTimeChecker {

        public static string[] detections = { "2020/02/09:00:55:22" }; /* Add your DPS detections here, An example string is in the array.*/

        public static string getCompileTime(string path) {
            const int c_PeHeaderOffset = 60;
            const int c_LinkerTimestampOffset = 8;

            var buffer = new byte[2048];

            using (var stream = new FileStream(path, FileMode.Open, System.IO.FileAccess.Read)) stream.Read(buffer, 0, 2048);

            for (int i = 0; i < 2048; i++) try { var test = BitConverter.ToInt32(buffer, i); } catch { }

            var offset = BitConverter.ToInt32(buffer, c_PeHeaderOffset);
            var secondsSince1970 = BitConverter.ToInt32(buffer, offset + c_LinkerTimestampOffset);
            var epoch = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);

            var linkTimeUtc = epoch.AddSeconds(secondsSince1970);

            var tz = null ?? TimeZoneInfo.Utc;
            var localTime = TimeZoneInfo.ConvertTimeFromUtc(linkTimeUtc, tz);

            DateTime date = Convert.ToDateTime(localTime);

            return date.ToString("yyyy/MM/dd:HH:mm:ss");
        }
    }
}
