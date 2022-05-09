using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace LamNT.MiTransport
{
    public static class ByteArrayExtensions
    {
        public static void WriteByte(this byte[] data, ref int position, byte value)
        {
            data[position] = value;
            position += 1;
        }

        public static byte ReadByte(this byte[] data, ref int position)
        {
            byte value = data[position];
            position += 1;
            return value;
        }

        public static void WriteInt(this byte[] data, ref int position, int value)
        {
            unsafe
            {
                fixed (byte* dataPtr = &data[position])
                {
                    int* valuePtr = (int*)dataPtr;
                    *valuePtr = value;
                    position += 4;
                }
            }
        }

        public static int ReadInt(this byte[] data, ref int position)
        {
            int value = BitConverter.ToInt32(data, position);
            position += 4;
            return value;
        }

        public static void WriteSegment(this byte[] data, ref int position, ArraySegment<byte> segment)
        {
            data.WriteInt(ref position, segment.Count);
            Array.Copy(segment.Array, segment.Offset, data, position, segment.Count);
            position += segment.Count;
        }

        public static ArraySegment<byte> ReadSegment(this byte[] data, ref int position)
        {
            int byteSize = data.ReadInt(ref position);

            byte[] value = new byte[byteSize];

            for (int i = 0; i < byteSize; i++)
                value[i] = data.ReadByte(ref position);

            return new ArraySegment<byte>(value);
        }
    }
}
