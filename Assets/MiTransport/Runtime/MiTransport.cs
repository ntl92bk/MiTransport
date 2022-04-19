using System;
using System.Collections.Generic;
using UnityEngine;
using Mirror;

namespace LamNT.MiTransport
{
    public enum OpCodes : byte
    {
        Handshake,
        Encrypted,
        Unencrypted
    }

    [DisallowMultipleComponent]
    public class MiTransport : Transport
    {
        [SerializeField] bool _logError;

        public string serverKey;
        public string clientKey;

        [ContextMenu("Random rsa keypair")]
        public void GenerateKeyPair()
        {
            (serverKey, clientKey) = RsaEncryption.GenerateXMLStrings();
        }

        public Transport _innerTransport;

        public bool showDebugLogs = false;
        private Dictionary<int, ServerToClientConnection> _tempServerToClientConnections;
        private Dictionary<int, ServerToClientConnection> _serverToClientConnections;
        private ClientToServerConnection _clientConnection;

        public override string ServerGetClientAddress(int connectionId) => _innerTransport.ServerGetClientAddress(connectionId);

        public override void ServerDisconnect(int connectionId) => _innerTransport.ServerDisconnect(connectionId);
        public override int GetMaxPacketSize(int channelId = 0) => _innerTransport.GetMaxPacketSize(channelId) - Constants.AesBlockSizeValue;
        public override void ServerEarlyUpdate() => _innerTransport.ServerEarlyUpdate();
        public override void ClientEarlyUpdate() => _innerTransport.ClientEarlyUpdate();
        public override void ClientDisconnect() => _innerTransport.ClientDisconnect();
        public override void ClientLateUpdate() => _innerTransport.ClientLateUpdate();
        public override void ServerLateUpdate() => _innerTransport.ServerLateUpdate();
        public override bool ClientConnected() => _innerTransport.ClientConnected();
        public override bool ServerActive() => _innerTransport.ServerActive();
        public override void ServerStop() => _innerTransport.ServerStop();
        public override bool Available() => _innerTransport.Available();
        public override Uri ServerUri() => _innerTransport.ServerUri();
        public override void Shutdown() => _innerTransport.Shutdown();

        private void Start()
        {
            SetupCallbacks();
        }

        private void SetupCallbacks()
        {
            _innerTransport.OnServerConnected = OnServerConnect;
            _innerTransport.OnServerDisconnected = OnServerDisconnect;
            _innerTransport.OnServerDataReceived = OnServerDataReceive;
            _innerTransport.OnServerError = (i, e) => OnServerError?.Invoke(i, e);

            _innerTransport.OnClientConnected = () => { _clientConnection = new ClientToServerConnection(_innerTransport, clientKey); _clientConnection.StartHandShake(); };
            _innerTransport.OnClientDataReceived = OnClientDataReceive;
            _innerTransport.OnClientDisconnected = () => OnClientDisconnected?.Invoke();
            _innerTransport.OnClientError = (e) => OnClientError?.Invoke(e);
        }

        private void OnServerConnect(int conn)
        {

        }

        void OnServerDataReceive(int conn, ArraySegment<byte> data, int channel)
        {
            try
            {
                var rawData = data.Array;
                int pos = data.Offset;

                OpCodes opcode = (OpCodes)rawData.ReadByte(ref pos);

                switch (opcode)
                {
                    case OpCodes.Handshake:
                        if (!_tempServerToClientConnections.ContainsKey(conn))
                        {
                            _tempServerToClientConnections.Add(conn, new ServerToClientConnection(conn, _innerTransport, serverKey));
                        }
                        var handshakeData = rawData.ReadSegment(ref pos);
                        _tempServerToClientConnections[conn].HandleReceived(handshakeData);

                        if (_tempServerToClientConnections[conn].IsHandShakeCompleted())
                        {
                            _serverToClientConnections.Add(conn, _tempServerToClientConnections[conn]);
                            OnServerConnected?.Invoke(conn);
                        }
                        break;
                    case OpCodes.Encrypted:
                        var length = rawData.ReadInt(ref pos);
                        var read = rawData.ReadSegment(ref pos);

                        if (_serverToClientConnections.ContainsKey(conn))
                        {
                            var decrypted = _serverToClientConnections[conn].DecryptEncryptedMessage(read);
                            OnServerDataReceived?.Invoke(conn, new ArraySegment<byte>(decrypted.Array, decrypted.Offset, length), channel);
                        }
                        break;
                    case OpCodes.Unencrypted:
                        if (_serverToClientConnections.ContainsKey(conn))
                        {
                            read = rawData.ReadSegment(ref pos);
                            OnServerDataReceived?.Invoke(conn, read, channel);
                        }
                        break;
                }
            }
            catch (Exception e)
            {
                if (_logError)
                    Debug.LogError("Error: " + e);
            }
        }

        void OnServerDisconnect(int conn)
        {
            _tempServerToClientConnections.Remove(conn);
            _serverToClientConnections.Remove(conn);

            OnServerDisconnected?.Invoke(conn);
        }

        private void OnClientDataReceive(ArraySegment<byte> data, int channel)
        {
            try
            {
                var rawData = data.Array;
                int pos = data.Offset;

                OpCodes opcode = (OpCodes)rawData.ReadByte(ref pos);

                switch (opcode)
                {
                    case OpCodes.Handshake:
                        var handshakeData = rawData.ReadSegment(ref pos);
                        _clientConnection.HandleReceived(handshakeData);

                        if (_clientConnection.IsHandShakeCompleted())
                        {
                            OnClientConnected?.Invoke();
                        }

                        break;
                    case OpCodes.Encrypted:
                        if (_clientConnection != null)
                        {
                            var length = rawData.ReadInt(ref pos);
                            var read = rawData.ReadSegment(ref pos);
                            var decrypted = _clientConnection.DecryptEncryptedMessage(read);
                            OnClientDataReceived?.Invoke(new ArraySegment<byte>(decrypted.Array, decrypted.Offset, length), channel);
                        }

                        break;
                    case OpCodes.Unencrypted:
                        if (_clientConnection != null)
                        {
                            var read = rawData.ReadSegment(ref pos);
                            OnClientDataReceived?.Invoke(read, channel);
                        }
                        break;
                }
            }
            catch (Exception e)
            {
                if (_logError)
                    Debug.LogError("Error: " + e);
            }
        }

        public override void ClientConnect(string address)
        {
            _innerTransport.ClientConnect(address);
        }

        public override void ClientConnect(Uri uri)
        {
            _innerTransport.ClientConnect(uri);
        }

        public override void ClientSend(ArraySegment<byte> segment, int channelId)
        {
            _clientConnection?.SendData(segment, channelId);
        }

        public override void ServerSend(int connectionId, ArraySegment<byte> segment, int channelId)
        {
            if (_tempServerToClientConnections.ContainsKey(connectionId))
            {
                _tempServerToClientConnections[connectionId].SendData(segment, channelId);
            }
        }

        public override void ServerStart()
        {
            _tempServerToClientConnections = new Dictionary<int, ServerToClientConnection>();
            _serverToClientConnections = new Dictionary<int, ServerToClientConnection>();
            _innerTransport.ServerStart();
        }
    }
}
