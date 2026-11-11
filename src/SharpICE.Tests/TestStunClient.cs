using SharpStun;
using System;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

namespace SharpICE.Tests
{
    /// <summary>The STUN client against a server of a few lines here, and the ICE agent's server reflexive candidates of it.</summary>
    [TestClass]
    public class TestStunClient
    {
        /// <summary>A STUN server of the Binding method: the address each request came from, back. It drops the first request.</summary>
        private sealed class TinyStunServer : IDisposable
        {
            private readonly Socket _socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            private readonly CancellationTokenSource _cts = new CancellationTokenSource();
            private int _requests;

            public TinyStunServer()
            {
                _socket.Bind(new IPEndPoint(IPAddress.Loopback, 0));
                Task.Run(Serve);
            }

            public IPEndPoint EndPoint => (IPEndPoint)_socket.LocalEndPoint;

            public int Requests => _requests;

            private async Task Serve()
            {
                byte[] buffer = new byte[1500];
                while (!_cts.IsCancellationRequested)
                {
                    SocketReceiveFromResult result;
                    try
                    {
                        result = await _socket.ReceiveFromAsync(new ArraySegment<byte>(buffer), SocketFlags.None, new IPEndPoint(IPAddress.Any, 0));
                    }
                    catch (Exception)
                    {
                        return;
                    }
                    var request = StunMessage.Parse(buffer, 0, result.ReceivedBytes);
                    if (request == null || Interlocked.Increment(ref _requests) == 1)
                        continue;
                    var response = new StunMessage(StunMethod.Binding, StunMessageClass.SuccessResponse, request.TransactionId)
                        .AddXorAddress((IPEndPoint)result.RemoteEndPoint);
                    _socket.SendTo(response.ToBytes(), result.RemoteEndPoint);
                }
            }

            public void Dispose()
            {
                _cts.Cancel();
                _socket.Dispose();
            }
        }

        [TestMethod]
        public async Task LearnsTheMappedAddressOfARetransmittedRequest()
        {
            using var server = new TinyStunServer();
            using var socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            socket.Bind(new IPEndPoint(IPAddress.Loopback, 0));

            var mapped = await StunClient.GetMappedAddressAsync(socket, server.EndPoint, TimeSpan.FromSeconds(3));

            Assert.AreEqual(socket.LocalEndPoint, mapped);
            Assert.IsTrue(server.Requests >= 2, "the first request was dropped: answered once retransmitted");
        }

        [TestMethod]
        public async Task ResolvesTheServersAddress()
        {
            Assert.AreEqual(new IPEndPoint(IPAddress.Parse("192.0.2.1"), 3478), await StunClient.ResolveAsync("192.0.2.1"));
            Assert.AreEqual(new IPEndPoint(IPAddress.Parse("192.0.2.1"), 19302), await StunClient.ResolveAsync("stun:192.0.2.1:19302"));
            Assert.AreEqual(new IPEndPoint(IPAddress.Parse("2001:db8::1"), 3478), await StunClient.ResolveAsync("[2001:db8::1]:3478", AddressFamily.InterNetworkV6));
            Assert.IsNull(await StunClient.ResolveAsync("192.0.2.1", AddressFamily.InterNetworkV6));
        }

        [TestMethod]
        public async Task GathersAServerReflexiveCandidate()
        {
            using var server = new TinyStunServer();
            var options = new IceAgentOptions
            {
                IncludeLoopback = true,
                AddressFilter = address => IPAddress.IsLoopback(address) && address.AddressFamily == AddressFamily.InterNetwork,
                StunServerTimeout = TimeSpan.FromSeconds(3),
            };
            options.StunServers.Add(server.EndPoint.ToString());
            using var agent = new IceAgent(options);

            // a loopback socket's mapping is of no use to a peer elsewhere: none is asked of a loopback base
            var candidates = await agent.GatherCandidatesAsync();

            Assert.AreEqual(1, candidates.Count);
            Assert.AreEqual(IceCandidateType.Host, candidates[0].Type);
            Assert.AreEqual(0, server.Requests);
        }
    }
}
