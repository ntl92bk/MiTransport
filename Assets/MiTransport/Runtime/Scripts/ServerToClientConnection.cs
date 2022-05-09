using System;
using System.Collections.Generic;
using UnityEngine;
using System.Security.Cryptography;
using System.Text;
using Mirror;
using System.Linq;

namespace LamNT.MiTransport
{
    public class ServerToClientConnection : IDisposable
    {
        private string _rsaXMLString;

        public enum State
        {
            Init,
            WaitForClientConfirm,
            HandshakeCompleted
        }

        public bool IsHandShakeCompleted() => _state == State.HandshakeCompleted;

        public State _state;

        private byte[] _clientHelloKey;
        private byte[] _clientHelloIV;

        private byte[] _serverHelloKey;
        private byte[] _serverHelloIV;
        private byte[] _finalKey;
        private byte[] _finalIV;

        Aes _finalAes;
        ICryptoTransform _finalEncryptor;
        ICryptoTransform _finalDecryptor;

        Transport _innerTransport;
        int _conn;

        public ServerToClientConnection(int conn, Transport innerTransport, string rsaXMLString)
        {
            _conn = conn;
            _rsaXMLString = rsaXMLString;
            _innerTransport = innerTransport;
            _sendBuffer = new byte[innerTransport.GetMaxPacketSize()];
            _encryptedBuffer = new byte[innerTransport.GetMaxPacketSize()];
        }

        private byte[] _sendBuffer;
        private byte[] _encryptedBuffer;

        public void HandleReceived(ArraySegment<byte> data)
        {
            if (_state == State.Init)
            {
                HandleClientHello(data);
            }
            else if (_state == State.WaitForClientConfirm)
            {
                HandleClientConfirm(data);
            }
        }

        void HandleClientHello(ArraySegment<byte> data)
        {
            var decrypted = DecryptClientHello(data);

            _clientHelloIV = new byte[Constants.AesBlockSizeValue];
            _clientHelloKey = new byte[Constants.AesKeySizeValue];

            Array.Copy(decrypted, 0, _clientHelloIV, 0, _clientHelloIV.Length);
            Array.Copy(decrypted, _clientHelloIV.Length, _clientHelloKey, 0, _clientHelloKey.Length);

            _state = State.WaitForClientConfirm;
            SendHelloToClient();
        }

        void HandleClientConfirm(ArraySegment<byte> data)
        {
            using (var aes = Aes.Create())
            {
                aes.Key = _finalKey;
                aes.IV = _finalIV;

                var decryptor = aes.CreateDecryptor();

                var decrypted = decryptor.TransformFinalBlockToArray(data);

                var text = System.Text.UTF8Encoding.UTF8.GetString(decrypted);
                if (text == Constants.ConfirmString)
                {
                    _state = State.HandshakeCompleted;
                }
            }
        }

        byte[] DecryptClientHello(ArraySegment<byte> data)
        {
            var decrypted = RsaEncryption.Decrypt(data.ToArray(), _rsaXMLString);
            return decrypted;
        }

        void SendHelloToClient()
        {
            // Random server key and iv
            using (Aes aes = Aes.Create())
            {
                aes.GenerateIV();
                aes.GenerateKey();
                _serverHelloIV = aes.IV;
                _serverHelloKey = aes.Key;

                CalculateFinalKeyAndIV();

                var compact = new byte[_serverHelloKey.Length + _serverHelloIV.Length];
                _serverHelloIV.CopyTo(compact, 0);
                _serverHelloKey.CopyTo(compact, _serverHelloIV.Length);

                SendWithClientAesEncrypt(compact);
            }
        }

        void SendWithClientAesEncrypt(byte[] data)
        {
            using (Aes aes = Aes.Create())
            {
                aes.IV = _clientHelloIV;
                aes.Key = _clientHelloKey;

                var compact = new byte[_serverHelloIV.Length + _serverHelloKey.Length];
                _serverHelloIV.CopyTo(compact, 0);
                _serverHelloKey.CopyTo(compact, _serverHelloIV.Length);

                var encryptor = aes.CreateEncryptor();
                var encrypted = encryptor.TransformFinalBlockToArray(new ArraySegment<byte>(compact, 0, compact.Length));

                Send(OpCodes.Handshake, new ArraySegment<byte>(encrypted));
            }
        }

        void Send(OpCodes op, ArraySegment<byte> data, int channel = Channels.Reliable)
        {
            int pos = 0;
            _sendBuffer.WriteByte(ref pos, (byte)op);
            _sendBuffer.WriteSegment(ref pos, data);
            _innerTransport.ServerSend(_conn, new ArraySegment<byte>(_sendBuffer, 0, pos), channel);
        }

        void SendEncrypted(OpCodes op, ArraySegment<byte> segment, int channel = Channels.Reliable)
        {
            Array.Copy(segment.Array, segment.Offset, _encryptedBuffer, 0, segment.Count);
            var expandLength = (segment.Count / Constants.AesBlockSizeValue + (segment.Count % Constants.AesBlockSizeValue == 0 ? 0 : 1)) * Constants.AesBlockSizeValue;
            var nSegment = new ArraySegment<byte>(_encryptedBuffer, 0, expandLength);
            var encrypted = _finalEncryptor.TransformBlockSegment(nSegment);

            int pos = 0;
            _sendBuffer.WriteByte(ref pos, (byte)op);
            _sendBuffer.WriteInt(ref pos, segment.Count);
            _sendBuffer.WriteSegment(ref pos, encrypted);
            _innerTransport.ServerSend(_conn, new ArraySegment<byte>(_sendBuffer, 0, pos), channel);
        }

        void CalculateFinalKeyAndIV()
        {
            _finalIV = AesTransformExtensions.Merge(_clientHelloIV, _serverHelloIV);
            _finalKey = AesTransformExtensions.Merge(_clientHelloKey, _serverHelloKey);

            _finalAes = Aes.Create();
            _finalAes.Key = _finalKey;
            _finalAes.IV = _finalIV;
            _finalAes.Padding = PaddingMode.None;
            _finalEncryptor = _finalAes.CreateEncryptor();
            _finalDecryptor = _finalAes.CreateDecryptor();
        }

        ~ServerToClientConnection()
        {
            Dispose(false);
        }

        public void Dispose()
        {
            Dispose(true);
        }

        private bool _disposed;

        void Dispose(bool dispose)
        {
            if (_disposed)
                return;

            _disposed = true;

            if (dispose)
            {
                _finalAes.Dispose();
                _finalEncryptor.Dispose();
                _finalDecryptor.Dispose();
            }
        }

        public ArraySegment<byte> DecryptEncryptedMessage(ArraySegment<byte> data)
        {
            var decrypted = _finalDecryptor.TransformBlockSegment(data);
            return decrypted;
        }


        public void SendData(ArraySegment<byte> segment, int channel)
        {
            if (channel == Channels.Reliable)
            {
                if (_state == State.HandshakeCompleted)
                {
                    SendEncrypted(OpCodes.Encrypted, segment, channel);
                }
            }
            else
            {
                Send(OpCodes.Unencrypted, segment, channel);
            }
        }
    }
}
