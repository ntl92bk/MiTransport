using System;
using System.Collections.Generic;
using System.Text;
using System.Security.Cryptography;
using System.IO;
using UnityEngine;
using Mirror;

namespace LamNT.MiTransport
{
    public class ClientToServerConnection : IDisposable
    {
        private string _rsaXMLString;

        public enum State
        {
            Init,
            HandshakeCompleted
        }

        public bool IsHandShakeCompleted() => _state == State.HandshakeCompleted;

        public State _state;

        byte[] _clientHelloKey;
        byte[] _clientHelloIV;
        private byte[] _serverHelloKey;
        private byte[] _serverHelloIV;
        private byte[] _finalKey;
        private byte[] _finalIV;

        Aes _finalAes;
        ICryptoTransform _finalEncryptor;
        ICryptoTransform _finalDecryptor;

        Transport _innerTransport;

        public ClientToServerConnection(Transport innerTransport, string rsaXMLString)
        {
            _innerTransport = innerTransport;
            _rsaXMLString = rsaXMLString;
            _sendBuffer = new byte[innerTransport.GetMaxPacketSize()];
            _encryptedBuffer = new byte[innerTransport.GetMaxPacketSize()];
        }

        private byte[] _sendBuffer;
        private byte[] _encryptedBuffer;

        public void StartHandShake()
        {
            SendHelloToServer();
        }

        public void HandleReceived(ArraySegment<byte> data)
        {
            if (_state == State.Init)
            {
                HandleServerHello(data);
            }
        }

        void SendHelloToServer()
        {
            using (Aes aes = Aes.Create())
            {
                aes.GenerateIV();
                aes.GenerateKey();

                _clientHelloIV = aes.IV;
                _clientHelloKey = aes.Key;

                var compact = new byte[_clientHelloKey.Length + _clientHelloIV.Length];
                _clientHelloIV.CopyTo(compact, 0);
                _clientHelloKey.CopyTo(compact, _clientHelloIV.Length);

                SendWithRsaEncrypt(compact);
            }
        }

        void SendConfirm()
        {
            using (var aes = Aes.Create())
            {
                aes.Key = _finalKey;
                aes.IV = _finalIV;

                var encryptor = aes.CreateEncryptor();

                var d = Encoding.ASCII.GetBytes(Constants.ConfirmString);
                var encrypted = encryptor.TransformFinalBlockToArray(new ArraySegment<byte>(d, 0, d.Length));
                Send(OpCodes.Handshake, new ArraySegment<byte>(encrypted));
                _state = State.HandshakeCompleted;
            }
        }

        void SendWithRsaEncrypt(byte[] data)
        {
            var encrypted = RsaEncryption.Encrypt(data, _rsaXMLString);
            Send(OpCodes.Handshake, new ArraySegment<byte>(encrypted));
        }

        void HandleServerHello(ArraySegment<byte> data)
        {
            var decrypted = DecryptServerHello(data);

            _serverHelloIV = new byte[Constants.AesBlockSizeValue];
            _serverHelloKey = new byte[Constants.AesKeySizeValue];

            Array.Copy(decrypted, 0, _serverHelloIV, 0, _serverHelloIV.Length);
            Array.Copy(decrypted, _serverHelloIV.Length, _serverHelloKey, 0, _serverHelloKey.Length);

            CalculateFinalKeyAndIV();

            SendConfirm();
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

        byte[] DecryptServerHello(ArraySegment<byte> data)
        {
            using (Aes aes = Aes.Create())
            {
                aes.IV = _clientHelloIV;
                aes.Key = _clientHelloKey;

                var decryptor = aes.CreateDecryptor();
                return decryptor.TransformFinalBlockToArray(data);
            }
        }

        void Send(OpCodes op, ArraySegment<byte> data, int channel = Channels.Reliable)
        {
            int pos = 0;
            _sendBuffer.WriteByte(ref pos, (byte)op);
            _sendBuffer.WriteSegment(ref pos, data);
            _innerTransport.ClientSend(new ArraySegment<byte>(_sendBuffer, 0, pos), channel);
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
            _innerTransport.ClientSend(new ArraySegment<byte>(_sendBuffer, 0, pos), channel);
        }

        ~ClientToServerConnection()
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
