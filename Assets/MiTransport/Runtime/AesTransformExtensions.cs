using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace LamNT.MiTransport
{
    public static class AesTransformExtensions
    {
        public static byte[] TransformFinalBlockToArray(this ICryptoTransform transform, ArraySegment<byte> data)
        {
            return transform.TransformFinalBlock(data.Array, data.Offset, data.Count);
        }

        public static ArraySegment<byte> TransformBlockSegment(this ICryptoTransform transform, ArraySegment<byte> data)
        {
            transform.TransformBlock(data.Array, data.Offset, data.Count, data.Array, 0);
            return data;
        }


        public static byte[] Merge(byte[] serverKey, byte[] clientKey)
        {
            if (serverKey == null || clientKey == null || serverKey.Length != clientKey.Length)
                throw new Exception("Keys are null or not same length");

            var output = new byte[serverKey.Length];
            serverKey.CopyTo(output, 0);

            for (int i = 0; i < output.Length; i++)
            {
                output[i] = (byte)(serverKey[i] ^ clientKey[i]);
            }

            return output;
        }

        public static string ByteArrayToString(byte[] ba)
        {
            StringBuilder hex = new StringBuilder(ba.Length * 2);
            foreach (byte b in ba)
                hex.AppendFormat("{0:x2}", b);
            return hex.ToString();
        }
    }
}
