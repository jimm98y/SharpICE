using SharpStun;
using System;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace SharpICE.Tests
{
    /// <summary>
    /// Two agents on this machine's loopback: their candidates and credentials exchanged as signalling would, checked, a pair
    /// nominated, and data sent both ways on it.
    /// </summary>
    [TestClass]
    public class TestIceAgent
    {
        private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(10);

        private static IceAgent CreateAgent(IceRole role) => new IceAgent(new IceAgentOptions
        {
            Role = role,
            IncludeLoopback = true,
            AddressFilter = address => IPAddress.IsLoopback(address) && address.AddressFamily == AddressFamily.InterNetwork,
        });

        private static async Task Connect(IceAgent a, IceAgent b)
        {
            await a.GatherCandidatesAsync();
            await b.GatherCandidatesAsync();
            a.SetRemoteCredentials(b.LocalUfrag, b.LocalPassword);
            b.SetRemoteCredentials(a.LocalUfrag, a.LocalPassword);
            foreach (var candidate in b.LocalCandidates)
                a.AddRemoteCandidate(candidate.ToString());
            foreach (var candidate in a.LocalCandidates)
                b.AddRemoteCandidate(candidate.ToString());

            a.Start();
            b.Start();

            // both connected, on a pair the controlling one nominated
            DateTime deadline = DateTime.UtcNow + Timeout;
            while (DateTime.UtcNow < deadline)
            {
                if (a.SelectedPair?.Nominated == true && b.SelectedPair?.Nominated == true)
                    return;
                await Task.Delay(20);
            }
            Assert.Fail($"Not connected: {a.State} {a.SelectedPair}, {b.State} {b.SelectedPair}");
        }

        private static async Task<string> SendAndReceive(IceAgent from, IceAgent to, string text)
        {
            var received = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);
            EventHandler<IceDataReceivedEventArgs> handler = (s, e) => received.TrySetResult(Encoding.UTF8.GetString(e.Buffer, e.Offset, e.Count));
            to.DataReceived += handler;
            try
            {
                byte[] bytes = Encoding.UTF8.GetBytes(text);
                Assert.IsTrue(from.Send(bytes, 0, bytes.Length));
                Assert.AreSame(received.Task, await Task.WhenAny(received.Task, Task.Delay(Timeout)));
                return await received.Task;
            }
            finally
            {
                to.DataReceived -= handler;
            }
        }

        [TestMethod]
        public async Task ConnectsAndSendsBothWays()
        {
            using var controlling = CreateAgent(IceRole.Controlling);
            using var controlled = CreateAgent(IceRole.Controlled);

            await Connect(controlling, controlled);

            Assert.AreEqual(IceConnectionState.Connected, controlling.State);
            Assert.AreEqual(IceConnectionState.Connected, controlled.State);
            Assert.AreEqual(controlling.SelectedPair.LocalEndPoint, controlled.SelectedPair.RemoteEndPoint);
            Assert.AreEqual(controlled.SelectedPair.LocalEndPoint, controlling.SelectedPair.RemoteEndPoint);
            Assert.AreEqual("hello", await SendAndReceive(controlling, controlled, "hello"));
            Assert.AreEqual("world", await SendAndReceive(controlled, controlling, "world"));
        }

        [TestMethod]
        public async Task ResolvesARoleConflict()
        {
            using var a = CreateAgent(IceRole.Controlling);
            using var b = CreateAgent(IceRole.Controlling);

            await Connect(a, b);

            Assert.AreNotEqual(a.Role, b.Role);
            Assert.AreEqual(a.TieBreaker > b.TieBreaker ? IceRole.Controlling : IceRole.Controlled, a.Role);
            Assert.AreEqual("both", await SendAndReceive(a, b, "both"));
        }

        [TestMethod]
        public async Task LearnsAPeerReflexiveCandidate()
        {
            // the controlled agent is told of no candidate: it learns the controlling one's of its checks
            using var controlling = CreateAgent(IceRole.Controlling);
            using var controlled = CreateAgent(IceRole.Controlled);
            await controlling.GatherCandidatesAsync();
            await controlled.GatherCandidatesAsync();
            controlling.SetRemoteCredentials(controlled.LocalUfrag, controlled.LocalPassword);
            controlled.SetRemoteCredentials(controlling.LocalUfrag, controlling.LocalPassword);
            foreach (var candidate in controlled.LocalCandidates)
                controlling.AddRemoteCandidate(candidate);
            controlling.Start();
            controlled.Start();

            DateTime deadline = DateTime.UtcNow + Timeout;
            while (DateTime.UtcNow < deadline && !(controlled.SelectedPair?.Nominated == true && controlling.SelectedPair?.Nominated == true))
                await Task.Delay(20);

            Assert.AreEqual(IceCandidateType.PeerReflexive, controlled.SelectedPair.Remote.Type);
            Assert.AreEqual("prflx", await SendAndReceive(controlled, controlling, "prflx"));
        }

        [TestMethod]
        public async Task IgnoresRequestsOfOtherCredentials()
        {
            using var agent = CreateAgent(IceRole.Controlled);
            await agent.GatherCandidatesAsync();
            var target = agent.LocalCandidates.Single().EndPoint;

            using var socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            socket.Bind(new IPEndPoint(IPAddress.Loopback, 0));
            // of a machine busy of the other tests: as long as they wait
            socket.ReceiveTimeout = 10000;
            var request = new StunMessage(StunMethod.Binding, StunMessageClass.Request)
                .AddString(StunAttributeType.Username, agent.LocalUfrag + ":peer")
                .AddUInt64(StunAttributeType.IceControlling, 1);
            socket.SendTo(request.ToBytes(StunMessage.ShortTermKey("not the password")), target);

            byte[] buffer = new byte[1500];
            int count = socket.Receive(buffer);
            var response = StunMessage.Parse(buffer, 0, count);
            Assert.AreEqual(StunMessageClass.ErrorResponse, response.Class);
            Assert.AreEqual(StunErrorCode.Unauthorized, response.Error.Value.Code);
            Assert.AreEqual(0, agent.RemoteCandidates.Count);
        }
    }
}
