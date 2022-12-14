using FluentAssertions;

namespace Tests;

public class TcpdumpUnitTests
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

        var parser = Lib.TcpDumpParser.ParsePackets(Lib.TcpDumpParser.CreateSourceAddressFilter(@"localhost\.\d+"), reader);

        var enumerator = parser.GetEnumerator();
        enumerator.MoveNext();
        var packet = enumerator.Current.Data;

        packet.Length.Should().Be(4);
        packet[0].Should().Be((byte)'o');
        packet[1].Should().Be((byte)'n');
        packet[2].Should().Be((byte)'e');
        packet[3].Should().Be((byte)'\n');

        enumerator.MoveNext();
        packet = enumerator.Current.Data;

        packet.Length.Should().Be(4);
        packet[0].Should().Be((byte)'t');
        packet[1].Should().Be((byte)'w');
        packet[2].Should().Be((byte)'o');
        packet[3].Should().Be((byte)'\n');

        enumerator.MoveNext();
        packet = enumerator.Current.Data;

        packet.Length.Should().Be(6);
        packet[0].Should().Be((byte)'t');
        packet[1].Should().Be((byte)'h');
        packet[2].Should().Be((byte)'r');
        packet[3].Should().Be((byte)'e');
        packet[4].Should().Be((byte)'e');
        packet[5].Should().Be((byte)'\n');

        enumerator.MoveNext();
        packet = enumerator.Current.Data;

        packet.Length.Should().Be(5);
        packet[0].Should().Be((byte)'f');
        packet[1].Should().Be((byte)'o');
        packet[2].Should().Be((byte)'u');
        packet[3].Should().Be((byte)'r');
        packet[4].Should().Be((byte)'\n');
    }

    [Fact]
    public void NonMatchingSourceRegex()
    {
        // Create a TextReader from the string
        using var reader = new StringReader(testcapture);
        var parser = Lib.TcpDumpParser.ParsePackets(Lib.TcpDumpParser.CreateSourceAddressFilter(@"zzzzz"), reader);

        parser.Count().Should().Be(0);
    }

    [Fact]
    public void FilterUnionBehaves()
    {
        // Given
        var linedata = new string[]{};

        var one = Lib.TcpDumpParser.FilterUnionAnd(_ => true);
        one(linedata).Should().BeTrue();

        var onefalse = Lib.TcpDumpParser.FilterUnionAnd(_ => false);    
        onefalse(linedata).Should().BeFalse();

        var twotrue = Lib.TcpDumpParser.FilterUnionAnd(_ => true, _ => true);
        twotrue(linedata).Should().BeTrue();

        var twofalse = Lib.TcpDumpParser.FilterUnionAnd(_ => true, _ => false);
        twofalse(linedata).Should().BeFalse();

        var twotruefalse = Lib.TcpDumpParser.FilterUnionAnd(_ => true, _ => false);
        twotruefalse(linedata).Should().BeFalse();

        var twotruefalsereversed = Lib.TcpDumpParser.FilterUnionAnd(_ => false, _ => true);
        twotruefalsereversed(linedata).Should().BeFalse();

    }
}