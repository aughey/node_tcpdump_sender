// Create a TextReader from stdin

using System.Net;
using System.Net.Sockets;

// Create a UDP socket that will send to localhost:12345

using var socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);

using var reader = new StreamReader(Console.OpenStandardInput());

var parser = Lib.TcpDumpParser.ParsePackets(new(@"localhost\.\d+"), reader);

var endpoint = new IPEndPoint(IPAddress.Loopback, 12345);
foreach (var packet in parser)
{
    System.Console.WriteLine($"Sending {packet.Length} bytes");
    socket.SendTo(packet, endpoint);
    await Task.Delay(100);
}