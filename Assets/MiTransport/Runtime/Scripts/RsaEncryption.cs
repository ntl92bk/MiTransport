using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace LamNT.MiTransport
{
    public class RsaEncryption
    {
        const int KEY_SIZE = 2048;

        public static (string, string) GenerateXMLStrings()
        {
            using (var csp = new RSACryptoServiceProvider(KEY_SIZE))
            {
                return (csp.ToXmlString(true), csp.ToXmlString(false));
            }
        }

        public static byte[] Encrypt(byte[] input, string xmlString)
        {
            using (var csp = new RSACryptoServiceProvider())
            {
                csp.FromXmlString(xmlString);
                return csp.Encrypt(input, false);
            }
        }

        public static byte[] Decrypt(byte[] encryptedBytes, string xmlString)
        {
            using (var csp = new RSACryptoServiceProvider())
            {
                csp.FromXmlString(xmlString);
                return csp.Decrypt(encryptedBytes, false);
            }
        }

        public static string Encrypt(string plainText, string xmlString)
        {
            using (var csp = new RSACryptoServiceProvider())
            {
                csp.FromXmlString(xmlString);
                var data = Encoding.Unicode.GetBytes(plainText);
                var cipher = csp.Encrypt(data, false);

                return Convert.ToBase64String(cipher);
            }
        }

        public static string Decrypt(string cipherText, string xmlString)
        {
            using (var csp = new RSACryptoServiceProvider())
            {
                csp.FromXmlString(xmlString);

                var dataBytes = Convert.FromBase64String(cipherText);
                var plainText = csp.Decrypt(dataBytes, false);

                return Encoding.Unicode.GetString(plainText);
            }
        }
    }
}
