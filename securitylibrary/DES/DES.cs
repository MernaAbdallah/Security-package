using System;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using System.Text;
using System.Threading.Tasks;
using static System.Net.WebRequestMethods;

namespace SecurityLibrary.DES
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class DES : CryptographicTechnique
    {
        public int[] IP = {
            58, 50, 42, 34, 26, 18, 10, 2,
            60, 52, 44, 36, 28, 20, 12, 4,
            62, 54, 46, 38, 30, 22, 14, 6,
            64, 56, 48, 40, 32, 24, 16, 8,
            57, 49, 41, 33, 25, 17, 9, 1,
            59, 51, 43, 35, 27, 19, 11, 3,
            61, 53, 45, 37, 29, 21, 13, 5,
            63, 55, 47, 39, 31, 23, 15, 7
        };
        private static int[] PC_1 = {
             57 , 49 , 41 , 33 , 25 , 17 , 9 ,
             1  , 58 , 50 , 42 , 34 , 26 , 18 ,
             10 , 2  , 59 , 51 , 43 , 35 , 27 ,
            19 , 11 , 3  , 60 , 52 , 44 , 36 ,
             63 , 55 , 47 , 39 , 31 , 23 , 15 ,
             7  , 62 , 54 , 46 , 38 , 30 , 22 ,
             14 , 6  , 61 , 53 , 45 , 37 , 29 ,
             21 , 13 , 5  , 28 , 20 , 12 , 4
        };

        public int[] IP_1 = {
        40, 8, 48, 16, 56, 24, 64, 32,
        39, 7, 47, 15, 55, 23, 63, 31,
        38, 6, 46, 14, 54, 22, 62, 30,
        37, 5, 45, 13, 53, 21, 61, 29,
        36, 4, 44, 12, 52, 20, 60, 28,
        35, 3, 43, 11, 51, 19, 59, 27,
        34, 2, 42, 10, 50, 18, 58, 26,
        33, 1, 41, 9, 49, 17, 57, 25
        };

        public int[] EBit = {
            32, 1, 2, 3, 4, 5,
            4, 5, 6, 7, 8, 9,
            8, 9, 10, 11, 12, 13,
            12, 13, 14, 15, 16, 17,
            16, 17, 18, 19, 20, 21,
            20, 21, 22, 23, 24, 25,
            24, 25, 26, 27, 28, 29,
            28, 29, 30, 31, 32, 1
        };

        public int[] P = {
                    16, 7, 20, 21,
                    29, 12, 28, 17,
                    1, 15, 23, 26,
                    5, 18, 31, 10,
                    2, 8, 24, 14,
                    32, 27, 3, 9,
                    19, 13, 30, 6,
                    22, 11, 4, 25,
        };

        public override string Decrypt(string cipherText, string key)
        {
            string[] plainText = new string[64];
            string[] L = new string[17];
            string[] R = new string[17];

            string cipherTextBinary = HexaToBinary(cipherText);
            string keyBinary = HexaToBinary(key);

            string[] GeneratedKeys = GenerateKeys(keyBinary);
            Console.WriteLine(GeneratedKeys.Count() + " Key Generated each of " + GeneratedKeys[0].Length + " Bit ");

            string[] cipherTextBinaryPerm = new string[64];

            int[] IPNegative1 = {
                40, 8, 48, 16, 56, 24, 64, 32,
                39, 7, 47, 15, 55, 23, 63, 31,
                38, 6, 46, 14, 54, 22, 62, 30,
                37, 5, 45, 13, 53, 21, 61, 29,
                36, 4, 44, 12, 52, 20, 60, 28,
                35, 3, 43, 11, 51, 19, 59, 27,
                34, 2, 42, 10, 50, 18, 58, 26,
                33, 1, 41, 9, 49, 17, 57, 25,
            };

            for (int i = 0; i < 64; i++)
            {
                cipherTextBinaryPerm[IPNegative1[i] - 1] = cipherTextBinary.ElementAt(i).ToString();
            }
            string cipherTextBinaryPerm_ = string.Concat(cipherTextBinaryPerm);

            for (int i = 0; i < 32; i++)
            {
                R[0] += cipherTextBinaryPerm_.ElementAt(i);
                L[0] += cipherTextBinaryPerm_.ElementAt(i + 32);
            }

            for (int i = 1; i < 17; i++)
            {
                R[i] = L[i - 1];

                // Mangler_Function
                int[] E_BIT = {
                    32, 1, 2, 3, 4, 5,
                    4, 5, 6, 7, 8, 9,
                    8, 9, 10, 11, 12, 13,
                    12, 13, 14, 15, 16, 17,
                    16, 17, 18, 19, 20, 21,
                    20, 21, 22, 23, 24, 25,
                    24, 25, 26, 27, 28, 29,
                    28, 29, 30, 31, 32, 1
                };
                string expansion = PermuatationFunction(E_BIT, R[i]);

                string expansion_xor = XOR(expansion, GeneratedKeys[16 - i]);

                string expansion_xor_sbox = "";
                for (int start = 0; start < expansion_xor.Length; start += 6)
                {
                    // Extract a 6-bit segment
                    string sixBitSegment = expansion_xor.Substring(start, 6);
                    expansion_xor_sbox += SBox(sixBitSegment, (start / 6) + 1);
                }

                string manglerFunctionOutput = PermuatationFunction(P, expansion_xor_sbox);

                L[i] = XOR(R[i - 1], manglerFunctionOutput);
            }

            string concLR = L[16] + R[16];

            int[] IP = {
                58, 50, 42, 34, 26, 18, 10, 2,
                60, 52, 44, 36, 28, 20, 12, 4,
                62, 54, 46, 38, 30, 22, 14, 6,
                64, 56, 48, 40, 32, 24, 16, 8,
                57, 49, 41, 33, 25, 17, 9, 1,
                59, 51, 43, 35, 27, 19, 11, 3,
                61, 53, 45, 37, 29, 21, 13, 5,
                63, 55, 47, 39, 31, 23, 15, 7
            };
            for (int i = 0; i < 64; i++)
            {
                plainText[IP[i] - 1] = concLR.ElementAt(i).ToString();
            }
            string plainText_ = string.Concat(plainText);
            Print("Plain Text", plainText_);

            string plainText_hexa = BinaryToHexa(plainText_);
            Print("Plain Text", plainText_hexa);

            return plainText_hexa;
        }

        public override string Encrypt(string plainText, string key)
        {
            string plaintextBinary = HexaToBinary(plainText);
            string keyBinary = HexaToBinary(key);
            string[] subKeys = GenerateKeys(keyBinary);
            string pt64 = PermuatationFunction(IP, plaintextBinary);
            string l = pt64.Substring(0, 32);
            string r = pt64.Substring(32, 32);

            for (int i = 0; i < 16; i++)
            {
                string expandedR = PermuatationFunction(EBit, r);

                string xorResult = XOR(expandedR, subKeys[i]);

                StringBuilder sboxResult = new StringBuilder();
                for (int j = 0; j < 48; j += 6)
                {
                    string segment = xorResult.Substring(j, 6);
                    sboxResult.Append(SBox(segment, (j / 6) + 1));
                }

                string permutedResult = PermuatationFunction(P, sboxResult.ToString());

                string newL = XOR(l, permutedResult);

                l = r;
                r = newL;
            }

            string encryptedText = PermuatationFunction(IP_1, r + l);

            return BinaryToHexa(encryptedText);
        }


        static void Print(string label, string text)
        {
            Console.WriteLine(label + ": " + text);
            Console.WriteLine(label + " Count: " + text.Length);
            Console.WriteLine(">_<");
        }

        static string HexaToBinary(string HexaDecimal)
        {
            HexaDecimal = HexaDecimal.Substring(2);

            // Convert hex to an unsigned long integer
            ulong number = Convert.ToUInt64(HexaDecimal, 16);

            // Convert to binary
            string binary = Convert.ToString((long)number, 2);

            // Pad the binary string so that its length is a multiple of 4
            int requiredLength = HexaDecimal.Length * 4;
            binary = binary.PadLeft(requiredLength, '0');

            return binary;
        }
        public static string BinaryToHexa(string binary)
        {
            // Initialize a StringBuilder for hex result
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

        static string PermuatationFunction(int[] PermuatationArray, string OldString)
        {
            string newString = "";

            for (int i = 0; i < PermuatationArray.Count(); i++)
            {
                newString += OldString.ElementAt(PermuatationArray[i] - 1);
            }

            return newString;
        }

        static string LeftCircularShift(string binary, int count)
        {
            // Ensure the count is positive and less than the length of the string
            count %= binary.Length;

            // Perform the left circular shift
            string shifted = binary.Substring(count) + binary.Substring(0, count);

            return shifted;
        }

        static string[] GenerateKeys(string Binarykey)
        {
            string[] C = new string[17];
            string[] D = new string[17];
            string[] GeneratedKeys = new string[16];

            Console.WriteLine("------------------------------Generating 16 Key------------------------------ ");

            int[] PC_1 = {
                57, 49, 41, 33, 25, 17, 9,
                1, 58, 50, 42, 34, 26, 18,
                10, 2, 59, 51, 43, 35, 27,
                19, 11, 3, 60, 52, 44, 36,
                63, 55, 47, 39, 31, 23, 15,
                7, 62, 54, 46, 38, 30, 22,
                14, 6, 61, 53, 45, 37, 29,
                21, 13, 5, 28, 20, 12, 4
            };

            string KeyPlus = PermuatationFunction(PC_1, Binarykey);
            Print("KeyPlus", KeyPlus);

            for (int i = 0; i < 28; i++)
            {
                C[0] += KeyPlus.ElementAt(i);
                D[0] += KeyPlus.ElementAt(i + 28);
            }
            Print("C0", C[0]);
            Print("D0", D[0]);

            int[] ShiftCD = {
                1, 1,
                2, 2, 2, 2, 2, 2,
                1,
                2, 2, 2, 2, 2, 2,
                1
            };

            for (int i = 1; i < 17; i++)
            {
                C[i] = LeftCircularShift(C[i - 1], ShiftCD[i - 1]);
                D[i] = LeftCircularShift(D[i - 1], ShiftCD[i - 1]);
            }
            Print("C2", C[2]); Print("C3", C[3]);
            Print("D2", D[2]); Print("D3", D[3]);

            int[] PC_2 = {
                14, 17, 11, 24, 1, 5,
                3, 28, 15, 6, 21, 10,
                23, 19, 12, 4, 26, 8,
                16, 7, 27, 20, 13, 2,
                41, 52, 31, 37, 47, 55,
                30, 40, 51, 45, 33, 48,
                44, 49, 39, 56, 34, 53,
                46, 42, 50, 36, 29, 32
            };

            for (int i = 0; i < 16; i++)
            {
                GeneratedKeys[i] = PermuatationFunction(PC_2, C[i + 1] + D[i + 1]);
            }
            Print("Key 1", GeneratedKeys[1]);

            Console.WriteLine("-------------------------------------Done------------------------------------- ");

            return GeneratedKeys;
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

        static string SBox(string input, int sTableNumber)
        {
            string row = $"{input[0]}{input[5]}";
            string column = $"{input[1]}{input[2]}{input[3]}{input[4]}";

            int[] s = new int[64];

            if (sTableNumber == 1)
            {
                s = new int[] {
                    14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7,
                    0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
                    4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0,
                    15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13
                };
            }
            else if (sTableNumber == 2)
            {
                s = new int[] {
                    15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10,
                    3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5,
                    0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15,
                    13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9
                };
            }
            else if (sTableNumber == 3)
            {
                s = new int[] {
                    10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8,
                    13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1,
                    13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7,
                    1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12
                };
            }
            else if (sTableNumber == 4)
            {
                s = new int[] {
                    7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15,
                    13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9,
                    10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4,
                    3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14
                };
            }
            else if (sTableNumber == 5)
            {
                s = new int[] {
                    2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9,
                    14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6,
                    4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14,
                    11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3
                };
            }
            else if (sTableNumber == 6)
            {
                s = new int[] {
                    12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11,
                    10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8,
                    9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6,
                    4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13
                };
            }
            else if (sTableNumber == 7)
            {
                s = new int[] {
                    4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1,
                    13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6,
                    1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2,
                    6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12
                };
            }
            else if (sTableNumber == 8)
            {
                s = new int[] {
                    13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7,
                    1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,
                    7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8,
                    2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11
                };
            }

            // outer 2 digits * lenght of row + inner digits
            int valueIndex = (Convert.ToInt32(row, 2) * 16) + Convert.ToInt32(column, 2);

            string output = Convert.ToString(s[valueIndex], 2).PadLeft(4, '0');

            return output;
        }

    }
}