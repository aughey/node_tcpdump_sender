// Create a TextReader from stdin

using System.Net;
using System.Net.Sockets;

// Create a UDP socket that will send to localhost:12345

using var socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);

var isLocalhost = Lib.TcpDumpParser.CreateSourceAddressFilter(@"localhost\.\d+");
var isUdp = Lib.TcpDumpParser.UDPPacket;
Lib.TcpDumpParser.PacketFilter filter = (linedata) =>
{
    return isLocalhost(linedata) && isUdp(linedata);
};

using var reader = new StreamReader(Console.OpenStandardInput());
var parser = Lib.TcpDumpParser.ParsePackets(filter, reader);

var endpoint = new IPEndPoint(IPAddress.Loopback, 12345);
foreach (var data in parser)
{
    var (message, headers) = data;
    System.Console.WriteLine($"Sending {message.Length} bytes");
    socket.SendTo(message, endpoint);
    await Task.Delay(100);
}