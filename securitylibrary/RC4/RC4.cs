using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.RC4
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class RC4 : CryptographicTechnique
    {
        public override string Decrypt(string cipherText, string key)
        {
            byte[] cipherInByte = ConvertToBytes(cipherText);
            byte[] keyInByte = ConvertToBytes(key);

            byte[] S = new byte[256];
            byte[] T = new byte[256]; // Holds the key repeated

            // Initialize S and T
            for (int l = 0; l < 256; l++)
            {
                S[l] = (byte)l;
                T[l] = keyInByte[l % keyInByte.Length];
            }

            // Initial Permutation
            int j = 0;
            for (int i = 0; i < 256; i++)
            {
                j = (j + S[i] + T[i]) % 256;
                Swap(S, i, j);
            }

            // Generate Keystream
            byte[] keystream = GenerateKeystream(S, cipherInByte.Length);

            // XOR in bytes
            byte[] decryptedBytes = new byte[cipherInByte.Length];

            for (int i = 0; i < cipherInByte.Length; i++)
            {
                decryptedBytes[i] = (byte)(cipherInByte[i] ^ keystream[i]);
            }


            string plainString;
            if (cipherText.StartsWith("0x"))
            {
                //plainString = BinaryToHexa();
                plainString = BytesToHexa(decryptedBytes);

                Console.WriteLine(plainString);
            }
            else
            {
                plainString = Encoding.GetEncoding(1252).GetString(decryptedBytes);

                Console.WriteLine(plainString);
            }

            return plainString;
        }


        public override string Encrypt(string plainText, string key)
        {
            byte[] plainInByte = ConvertToBytes(plainText);
            byte[] keyInByte = ConvertToBytes(key);

            byte[] S = new byte[256];
            byte[] T = new byte[256]; // Holds the key repeated

            // Initialize S and T
            for (int l = 0; l < 256; l++)
            {
                S[l] = (byte)l;
                T[l] = keyInByte[l % keyInByte.Length];
            }

            // Initial Permutation
            int j = 0;
            for (int i = 0; i < 256; i++)
            {
                j = (j + S[i] + T[i]) % 256;
                Swap(S, i, j);
            }

            // Generate Keystream
            byte[] keystream = GenerateKeystream(S, plainInByte.Length);

            // XOR with binary
            string cipher = XOR(ByteToBinary(plainInByte), ByteToBinary(keystream));

            string cipherString;
            if (plainText.StartsWith("0x"))
            {
                cipherString = BinaryToHexa(cipher);

                Console.WriteLine(cipherString);
            }
            else
            {
                cipherString = BinaryStringToAscii(cipher);

                Console.WriteLine(cipherString);
            }

            return cipherString;
        }

        //keystream based on the permutation array S
        private byte[] GenerateKeystream(byte[] S, int length)
        {
            byte[] keystream = new byte[length];
            int i = 0, j = 0;

            for (int k = 0; k < length; k++)
            {
                i = (i + 1) % 256;
                j = (j + S[i]) % 256;

                Swap(S, i, j);

                int t = (S[i] + S[j]) % 256;

                keystream[k] = S[t];
            }

            return keystream;
        }

        public static byte[] ConvertToBytes(string inputString)
        {
            if (inputString.StartsWith("0x"))
            {
                string hexaString = inputString.Substring(2);
                int lengthOfString = hexaString.Length;

                byte[] bytes = new byte[lengthOfString / 2];
                for (int i = 0; i < lengthOfString; i += 2)
                {
                    string hexaPair = hexaString.Substring(i, 2);
                    bytes[i / 2] = Convert.ToByte(hexaPair, 16);
                }
                return bytes;
            }
            else
            {
                // Convert string to bytes 1252 encoding "abcd maps to ÏíDu" after encoding
                return Encoding.GetEncoding(1252).GetBytes(inputString);
            }
        }


        public static void Swap(byte[] array, int first, int second)
        {
            byte temp = array[first];
            array[first] = array[second];
            array[second] = temp;
        }

        public static string ByteToBinary(byte[] byteArray)
        {
            StringBuilder binaryString = new StringBuilder();

            foreach (byte b in byteArray)
            {
                binaryString.Append(Convert.ToString(b, 2).PadLeft(8, '0'));
            }

            return binaryString.ToString();
        }

        static string XOR(string binaryStr1, string binaryStr2)
        {
            int maxLength = Math.Max(binaryStr1.Length, binaryStr2.Length);

            // Convert binary strings to numbers
            long num1 = Convert.ToInt64(binaryStr1, 2);
            long num2 = Convert.ToInt64(binaryStr2, 2);

            // Apply XOR operation
            long xorResult = num1 ^ num2;

            // Convert the result back to a binary string
            string result = Convert.ToString(xorResult, 2).PadLeft(maxLength, '0');

            return result;
        }

        public static string BytesToHexa(byte[] bytes)
        {
            // Convert the byte array to a hexadecimal string
            string hexa = BitConverter.ToString(bytes);

            // Remove any dashes that are included by default in the output
            hexa = hexa.Replace("-", "");

            hexa = "0x" + hexa;

            return hexa;
        }

        public static string BinaryToHexa(string binary)
        {
            string hexa = "";

            // Process each 4-bit segment of the binary string
            for (int i = 0; i < binary.Length; i += 4)
            {
                // Take a 4-bit segment
                string fourBitSegment = binary.Substring(i, 4);

                // Convert binary to an unsigned long integer
                ulong number = Convert.ToUInt64(fourBitSegment, 2);

                // Convert to hexadecimal
                hexa += Convert.ToString((long)number, 16).ToUpper();
            }

            hexa = "0x" + hexa;

            return hexa;
        }

        static string BinaryStringToAscii(string binaryString)
        {
            string ascii = "";

            for (int i = 0; i < binaryString.Length; i += 8)
            {
                // Take 8 bits at a time
                string byteString = binaryString.Substring(i, 8);
                // Convert these 8 bits to a byte (integer)
                byte byteValue = Convert.ToByte(byteString, 2);
                // Convert the byte to a character
                char character = (char)byteValue;
                // Append the character to the result
                ascii += character;
            }

            return ascii;
        }
    }
}