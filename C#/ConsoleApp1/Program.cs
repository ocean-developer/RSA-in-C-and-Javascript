using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;

namespace ConsoleApp1
{
    class Program
    {
        static void Main(string[] args)
        {
            demo();

        }

        public static void demo()
        { 
            Console.WriteLine("-------------------------------------------");
            Console.WriteLine("This is C# encryption demo");
            Console.WriteLine("-------------------------------------------");

            string[] keys = generateKeys(2048);

            string publicKeyString = keys[0];
            string privateKeyString = keys[1];


            string textToEncrypt = GenerateTestString();
            Console.WriteLine("TEKST DO ZASZYFROWANIA: ");
            Console.WriteLine(textToEncrypt);
            Console.WriteLine("-------------------------------------------");

            string encryptedText = Encrypt(textToEncrypt, publicKeyString); //Szyfrowanie za pomocą klucza publicznego
            Console.WriteLine("Encrypted TEXT: ");
            Console.WriteLine(b64ToHex(encryptedText));
            Console.WriteLine("-------------------------------------------");

            string decryptedText = Decrypt(encryptedText, privateKeyString); //Odszyfrowywanie za pomocą klucza prywatnego

            Console.WriteLine("Decrypted TEXT: ");
            Console.WriteLine(decryptedText);

        }

        public static string[] generateKeys(int keySize)
        {
            var cryptoServiceProvider = new RSACryptoServiceProvider(keySize); //2048 - Długość klucza
            var privateKey = cryptoServiceProvider.ExportParameters(true); //Generowanie klucza prywatnego
            var publicKey = cryptoServiceProvider.ExportParameters(false); //Generowanie klucza publiczny

            string publicKeyString = GetKeyString(publicKey);
            string privateKeyString = GetKeyString(privateKey);

            string[] keys = new string[2];

            keys[0] = publicKeyString;
            keys[1] = privateKeyString;

            Console.WriteLine("Module ");
            Console.WriteLine(bytesToHex(publicKey.Modulus));
            Console.WriteLine("-------------------------------------------");

            Console.WriteLine("Exponent");
            Console.WriteLine(bytesToHex(publicKey.Exponent));
            Console.WriteLine("-------------------------------------------");


            Console.WriteLine("D");
            Console.WriteLine(bytesToHex(privateKey.D));
            Console.WriteLine("-------------------------------------------");


            Console.WriteLine("P");
            Console.WriteLine(bytesToHex(privateKey.P));
            Console.WriteLine("-------------------------------------------");


            Console.WriteLine("Q");
            Console.WriteLine(bytesToHex(privateKey.Q));
            Console.WriteLine("-------------------------------------------");


            Console.WriteLine("DP");
            Console.WriteLine(bytesToHex(privateKey.DP));
            Console.WriteLine("-------------------------------------------");


            Console.WriteLine("DQ");
            Console.WriteLine(bytesToHex(privateKey.DQ));
            Console.WriteLine("-------------------------------------------");

            Console.WriteLine("Inverse Q");
            Console.WriteLine(bytesToHex(privateKey.InverseQ));
            Console.WriteLine("-------------------------------------------");

            return keys;
        }

        public static string b64ToHex(string s)
        {
            byte[] convertedByte = Encoding.Default.GetBytes(s);

            string hex = BitConverter.ToString(convertedByte);

            return hex.Replace("-", "");
        }
        public static string bytesToHex(byte[] b)
        {
            string hex = BitConverter.ToString(b);

            return hex.Replace("-", "");
        }

        public static string GetKeyString(RSAParameters publicKey)
        {

            var stringWriter = new System.IO.StringWriter();
            var xmlSerializer = new System.Xml.Serialization.XmlSerializer(typeof(RSAParameters));
            xmlSerializer.Serialize(stringWriter, publicKey);
            return stringWriter.ToString();
        }

        public static string Encrypt(string textToEncrypt, string publicKeyString)
        {
            var bytesToEncrypt = Encoding.UTF8.GetBytes(textToEncrypt);

            using (var rsa = new RSACryptoServiceProvider(2048))
            {
                try
                {
                    rsa.FromXmlString(publicKeyString.ToString());
                    var encryptedData = rsa.Encrypt(bytesToEncrypt, true);
                    var base64Encrypted = Convert.ToBase64String(encryptedData);
                    return base64Encrypted;
                }
                finally
                {
                    rsa.PersistKeyInCsp = false;
                }
            }
        }

        public static string Decrypt(string textToDecrypt, string privateKeyString)
        {
            var bytesToDescrypt = Encoding.UTF8.GetBytes(textToDecrypt);

            using (var rsa = new RSACryptoServiceProvider(2048))
            {
                try
                {

                    // server decrypting data with private key                    
                    rsa.FromXmlString(privateKeyString);

                    var resultBytes = Convert.FromBase64String(textToDecrypt);
                    var decryptedBytes = rsa.Decrypt(resultBytes, true);
                    var decryptedData = Encoding.UTF8.GetString(decryptedBytes);
                    return decryptedData.ToString();
                }
                finally
                {
                    rsa.PersistKeyInCsp = false;
                }
            }
        }

        private static string GenerateTestString()
        {
            Guid opportinityId = Guid.NewGuid();
            Guid systemUserId = Guid.NewGuid();
            string currentTime = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss");

            StringBuilder sb = new StringBuilder();
            sb.AppendFormat("opportunityid={0}", opportinityId.ToString());
            sb.AppendFormat("&systemuserid={0}", systemUserId.ToString());
            sb.AppendFormat("&currenttime={0}", currentTime);

            return sb.ToString();
        }
    }
}
