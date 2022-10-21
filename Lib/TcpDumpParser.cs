using System.Text.RegularExpressions;

namespace Lib;

// a sample tcpdump looks like
// 00:05:45.639941 IP6 localhost.52198 > localhost.12345: UDP, length 4
// 	0x0000:  6007 7c0f 000c 1140 0000 0000 0000 0000
// 	0x0010:  0000 0000 0000 0001 0000 0000 0000 0000
// 	0x0020:  0000 0000 0000 0001 cbe6 3039 000c 001f
// 	0x0030:  6f6e 650a
// 00:05:47.269266 IP6 localhost.59507 > localhost.12345: UDP, length 4
// 	0x0000:  6002 f3bb 000c 1140 0000 0000 0000 0000
// 	0x0010:  0000 0000 0000 0001 0000 0000 0000 0000
// 	0x0020:  0000 0000 0000 0001 e873 3039 000c 001f
// 	0x0030:  7477 6f0a
// 00:05:50.066262 IP6 localhost.50032 > localhost.12345: UDP, length 6
// 	0x0000:  600b 5789 000e 1140 0000 0000 0000 0000
// 	0x0010:  0000 0000 0000 0001 0000 0000 0000 0000
// 	0x0020:  0000 0000 0000 0001 c370 3039 000e 0021
// 	0x0030:  7468 7265 650a
// 00:05:53.238339 IP6 localhost.50768 > localhost.12345: UDP, length 5
// 	0x0000:  6008 1179 000d 1140 0000 0000 0000 0000
// 	0x0010:  0000 0000 0000 0001 0000 0000 0000 0000
// 	0x0020:  0000 0000 0000 0001 c650 3039 000d 0020
// 	0x0030:  666f 7572 0a

public class TcpDumpParser
{
    // Create an enumerable that will take a ITextReader and emit raw packets
    public static IEnumerable<byte[]> ParsePackets(System.Text.RegularExpressions.Regex sourceregex, TextReader reader)
    {
        // While reader still has stuff to read
        while (reader.Peek() != -1)
        {
            // Read a line
            var line = reader.ReadLine();
            if (line is null) { break; }

            // It must start with a number/timestamp


            // If it starts with a number, it's a timestamp
            if (!char.IsDigit(line[0]))
            {
                throw new Exception("Expected a timestamp");
            }

            // Parse the current line
            var linedata = line.Split(' ');

            if (AcceptablePacket(sourceregex, linedata))
            {
                var message = ReadData(reader);
                yield return message;
            }
            else
            {
                EatData(reader);
            }

        }
    }

    private static bool AcceptablePacket(Regex sourceregex, string[] linedata)
    {
        var protocol = linedata[5];
        if (protocol != "UDP,")
        {
            return false;
        }

        var source = linedata[2];
        if (!sourceregex.IsMatch(source))
        {
            return false;
        }

        return true;
    }

    private static byte[] ReadData(TextReader reader)
    {
        // Data looks like
        // 0x0000:  600b 5789 000e 1140 0000 0000 0000 0000
        // 0x0010:  0000 0000 0000 0001 0000 0000 0000 0000
        // 0x0020:  0000 0000 0000 0001 c370 3039 000e 0021
        // 0x0030:  7468 7265 650a

        // While next char is a tab
        List<string> words = new List<string>();
        while (reader.Peek() == '\t')
        {
            // Read a line
            var line = reader.ReadLine();
            if (line is null) { break; }

            // Parse the current line
            var linedata = line.Split(' ');
            // drop the first and second word
            var data = linedata.Skip(2);
            words.AddRange(data);
        }
        // Skip the first 22 words
        var message = words.Skip(24);

        // Strings in message that are 4 chars long are two hex bytes, split them
        var bytes = message.SelectMany(x => x.Length == 4 ? new[] { x.Substring(0, 2), x.Substring(2, 2) } : new[] { x });

        // Interpret each byte in the message as a 9-bit hex number
        return bytes.Select(x => Convert.ToByte(x, 16)).ToArray();

    }

    private static void EatData(TextReader reader)
    {
        // Read data while there is a tab in first character
        while (reader.Peek() == '\t')
        {
            reader.ReadLine();
        }
    }
}
