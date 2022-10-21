using FluentAssertions;

namespace Tests;

public class UnitTest1
{

    static readonly string testcapture = @"00:05:45.639941 IP6 localhost.52198 > localhost.12345: UDP, length 4
	0x0000:  6007 7c0f 000c 1140 0000 0000 0000 0000
	0x0010:  0000 0000 0000 0001 0000 0000 0000 0000
	0x0020:  0000 0000 0000 0001 cbe6 3039 000c 001f
	0x0030:  6f6e 650a
00:05:47.269266 IP6 localhost.59507 > localhost.12345: UDP, length 4
	0x0000:  6002 f3bb 000c 1140 0000 0000 0000 0000
	0x0010:  0000 0000 0000 0001 0000 0000 0000 0000
	0x0020:  0000 0000 0000 0001 e873 3039 000c 001f
	0x0030:  7477 6f0a
00:05:50.066262 IP6 localhost.50032 > localhost.12345: UDP, length 6
	0x0000:  600b 5789 000e 1140 0000 0000 0000 0000
	0x0010:  0000 0000 0000 0001 0000 0000 0000 0000
	0x0020:  0000 0000 0000 0001 c370 3039 000e 0021
	0x0030:  7468 7265 650a
00:05:53.238339 IP6 localhost.50768 > localhost.12345: UDP, length 5
	0x0000:  6008 1179 000d 1140 0000 0000 0000 0000
	0x0010:  0000 0000 0000 0001 0000 0000 0000 0000
	0x0020:  0000 0000 0000 0001 c650 3039 000d 0020
	0x0030:  666f 7572 0a";

    [Fact]
    public void TestParse()
    {
        // Create a TextReader from the string
        using var reader = new StringReader(testcapture);
        foreach(var packet in Lib.TcpDumpParser.ParsePackets(reader)) {
            packet.Length.Should().Be(4);
            packet[0].Should().Be((byte)'o');
            packet[1].Should().Be((byte)'n');
            packet[2].Should().Be((byte)'e');
            packet[3].Should().Be((byte)'\n');
            break;
        }
    }
}