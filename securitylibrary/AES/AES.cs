using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Numerics;

namespace SecurityLibrary.AES
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class AES : CryptographicTechnique
    {
        string[,] isBox = new string[16, 16] {
                { "52", "09", "6A", "D5", "30", "36", "A5", "38", "BF", "40", "A3", "9E", "81", "F3", "D7", "FB" },
                { "7C", "E3", "39", "82", "9B", "2F", "FF", "87", "34", "8E", "43", "44", "C4", "DE", "E9", "CB" },
                { "54", "7B", "94", "32", "A6", "C2", "23", "3D", "EE", "4C", "95", "0B", "42", "FA", "C3", "4E" },
                { "08", "2E", "A1", "66", "28", "D9", "24", "B2", "76", "5B", "A2", "49", "6D", "8B", "D1", "25" },
                { "72", "F8", "F6", "64", "86", "68", "98", "16", "D4", "A4", "5C", "CC", "5D", "65", "B6", "92" },
                { "6C", "70", "48", "50", "FD", "ED", "B9", "DA", "5E", "15", "46", "57", "A7", "8D", "9D", "84" },
                { "90", "D8", "AB", "00", "8C", "BC", "D3", "0A", "F7", "E4", "58", "05", "B8", "B3", "45", "06" },
                { "D0", "2C", "1E", "8F", "CA", "3F", "0F", "02", "C1", "AF", "BD", "03", "01", "13", "8A", "6B" },
                { "3A", "91", "11", "41", "4F", "67", "DC", "EA", "97", "F2", "CF", "CE", "F0", "B4", "E6", "73" },
                { "96", "AC", "74", "22", "E7", "AD", "35", "85", "E2", "F9", "37", "E8", "1C", "75", "DF", "6E" },
                { "47", "F1", "1A", "71", "1D", "29", "C5", "89", "6F", "B7", "62", "0E", "AA", "18", "BE", "1B" },
                { "FC", "56", "3E", "4B", "C6", "D2", "79", "20", "9A", "DB", "C0", "FE", "78", "CD", "5A", "F4" },
                { "1F", "DD", "A8", "33", "88", "07", "C7", "31", "B1", "12", "10", "59", "27", "80", "EC", "5F" },
                { "60", "51", "7F", "A9", "19", "B5", "4A", "0D", "2D", "E5", "7A", "9F", "93", "C9", "9C", "EF" },
                { "A0", "E0", "3B", "4D", "AE", "2A", "F5", "B0", "C8", "EB", "BB", "3C", "83", "53", "99", "61" },
                { "17", "2B", "04", "7E", "BA", "77", "D6", "26", "E1", "69", "14", "63", "55", "21", "0C", "7D" }
    };

        string[,] sBox = new string[16, 16] {
                { "63", "7c", "77", "7b", "f2", "6b", "6f", "c5", "30", "01", "67", "2b", "fe", "d7", "ab", "76"},
      { "ca", "82", "c9", "7d", "fa", "59", "47", "f0", "ad", "d4", "a2", "af", "9c", "a4", "72", "c0"},
      { "b7", "fd", "93", "26", "36", "3f", "f7", "cc", "34", "a5", "e5", "f1", "71", "d8", "31", "15"},
     { "04", "c7", "23", "c3", "18", "96", "05", "9a", "07", "12", "80", "e2", "eb", "27", "b2", "75"},
      { "09", "83", "2c", "1a", "1b", "6e", "5a", "a0", "52", "3b", "d6", "b3", "29", "e3", "2f", "84"},
      { "53", "d1", "00", "ed", "20", "fc", "b1", "5b", "6a", "cb", "be", "39", "4a", "4c", "58", "cf"},
      { "d0", "ef", "aa", "fb", "43", "4d", "33", "85", "45", "f9", "02", "7f", "50", "3c", "9f", "a8"},
      { "51", "a3", "40", "8f", "92", "9d", "38", "f5", "bc", "b6", "da", "21", "10", "ff", "f3", "d2"},
      { "cd", "0c", "13", "ec", "5f", "97", "44", "17", "c4", "a7", "7e", "3d", "64", "5d", "19", "73"},
     { "60", "81", "4f", "dc", "22", "2a", "90", "88", "46", "ee", "b8", "14", "de", "5e", "0b", "db"},
     { "e0", "32", "3a", "0a", "49", "06", "24", "5c", "c2", "d3", "ac", "62", "91", "95", "e4", "79"},
     { "e7", "c8", "37", "6d", "8d", "d5", "4e", "a9", "6c", "56", "f4", "ea", "65", "7a", "ae", "08"},
     { "ba", "78", "25", "2e", "1c", "a6", "b4", "c6", "e8", "dd", "74", "1f", "4b", "bd", "8b", "8a"},
      { "70", "3e", "b5", "66", "48", "03", "f6", "0e", "61", "35", "57", "b9", "86", "c1", "1d", "9e"},
      { "e1", "f8", "98", "11", "69", "d9", "8e", "94", "9b", "1e", "87", "e9", "ce", "55", "28", "df"},
      { "8c", "a1", "89", "0d", "bf", "e6", "42", "68", "41", "99", "2d", "0f", "b0", "54", "bb", "16"}
            };

        string[,] Rcon = {
    {"01", "02", "04", "08", "10", "20", "40", "80", "1b", "36"},
    {"00", "00", "00", "00", "00", "00", "00", "00", "00", "00"},
    {"00", "00", "00", "00", "00", "00", "00", "00", "00", "00"},
    {"00", "00", "00", "00", "00", "00", "00", "00", "00", "00"}
};
        int[,] invCoefficients = new int[4, 4]
{
    { 0x0E, 0x0B, 0x0D, 0x09 },
    { 0x09, 0x0E, 0x0B, 0x0D },
    { 0x0D, 0x09, 0x0E, 0x0B },
    { 0x0B, 0x0D, 0x09, 0x0E }
};
        int rconColumn = 0;
        public override string Decrypt(string cipherText, string key)
        {
            rconColumn = 0;
            string plain = "";
            // Remove "0x" from strings
            if (cipherText.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
            {
                cipherText = cipherText.Substring(2);
            }
            if (key.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
            {
                key = key.Substring(2);
            }
            string[,] cipherMatrix = new string[4, 4];
            string[,] keyMatrix = new string[4, 4];
            string[,] tempkey = new string[4, 4];

            // a list of the 10 generted round keys  
            List<string[,]> Roundkeys = new List<string[,]> { };
            //convert from block to state form 
            cipherMatrix = CTmatrixGeneration(cipherText);
            keyMatrix = CTmatrixGeneration(key);

            tempkey = keyMatrix;
            //we have 10 rounds , so we will generate 10 keys from the original key 
            int count = 0;
            while (count < 10)
            {
                keyMatrix = generateRoundKeys(keyMatrix, Rcon);
                Roundkeys.Add(keyMatrix);
                count++;
            }

            //perform XOR berween CT and last key before te 4 steps
            cipherMatrix = AddRoundKey(cipherMatrix, Roundkeys[9]);

            //from round 1 - 9 we do the following using CT and KEY :
            //1 - i shifRows
            //2 - i subBytes
            //3 - addRoundKey
            //4 - i mixCols
            //in the las round we do : 
            //1 - i shifRows
            //2 - i subBytes
            //3 - addRoundKey
            //then we get the PT
            int m = 9;
            while (m >= 0)
            {
                if (m != 0)
                {
                    cipherMatrix = inverseShiftRows(cipherMatrix);
                    cipherMatrix = inverseSubBytes(cipherMatrix);
                    cipherMatrix = AddRoundKey(cipherMatrix, Roundkeys[m - 1]);
                    cipherMatrix = inverseMixColumns(cipherMatrix);
                }
                else
                {
                    cipherMatrix = inverseShiftRows(cipherMatrix);
                    cipherMatrix = inverseSubBytes(cipherMatrix);
                    cipherMatrix = AddRoundKey(cipherMatrix, tempkey);
                }
                m--;
            }

            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    plain += cipherMatrix[j, i];
                }
            }
            plain = "0x" + plain;
            return plain;
        }

        public override string Encrypt(string plainText, string key)
        {
            //This method converts the input strings into a 2D array of strings,
            //with each element representing a pair of hexadecimal characters from the input strings.
            string[,] plain2d = mernaGenerator(plainText);
            string[,] roundKey = mernaGenerator(key);

            string[,] Add_merna_RoundKeyPlain2d = Add_merna_RoundKey(plain2d, roundKey);

            for (int round = 0; round < 10; round++)
            {
                //1 sub byte
                string[,] subPlain2d = substitution_merna_bytes(Add_merna_RoundKeyPlain2d);


                //2
                string[,] shiftPlain2d = shiftRows(subPlain2d);

                if (round < 9)
                {
                    // 3 
                    string[,] mixColumnsPlain2d = MixColumns(shiftPlain2d);

                    //4 
                    //Generates a new round key based on the previous round key
                    //Performs the XOR operation between the state and the round key.
                    roundKey = generate_merna_key(roundKey, round);
                    Add_merna_RoundKeyPlain2d = Add_merna_RoundKey(mixColumnsPlain2d, roundKey);
                }
                else
                {
                    roundKey = generate_merna_key(roundKey, round);
                    Add_merna_RoundKeyPlain2d = Add_merna_RoundKey(shiftPlain2d, roundKey);
                }
            }

            string cipher = string.Empty;
            for (int column = 0; column < 4; column++)
            {
                for (int row = 0; row < 4; row++)
                {
                    // Add_merna_RoundKeyPlain2d which represents the final state after all encryption rounds.
                    cipher += Add_merna_RoundKeyPlain2d[row, column];
                }
                // After the nested loops complete, the cipher string contains the binary representation of the encrypted data.
            }

            //represents the binary data in hexadecimal format.
            cipher = "0x" + cipher.ToUpper();

            return cipher;
        }

        string[,] mernaGenerator(string plainText)
        {
            //converting a string of plaintext into a 4x4 matrix(2D array) of hexadecimal strings.
            string[,] plain2d = new string[4, 4];

            int x = 2;
            //H 48

            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {

                    plain2d[j, i] = string.Concat(plainText[x], plainText[x + 1]);
                    x += 2;
                }
            }
            return plain2d;
        }


        public static string[,] S_Box = {
    {  "63", "7c", "77", "7b", "f2", "6b", "6f", "c5", "30", "01", "67", "2b", "fe", "d7", "ab", "76" },
    { "ca", "82", "c9", "7d", "fa", "59", "47", "f0", "ad", "d4", "a2", "af", "9c", "a4", "72", "c0" },
    {  "b7", "fd", "93", "26", "36", "3f", "f7", "cc", "34", "a5", "e5", "f1", "71", "d8", "31", "15" },
    {  "04", "c7", "23", "c3", "18", "96", "05", "9a", "07", "12", "80", "e2", "eb", "27", "b2", "75" },
    {  "09", "83", "2c", "1a", "1b", "6e", "5a", "a0", "52", "3b", "d6", "b3", "29", "e3", "2f", "84" },
    {  "53", "d1", "00", "ed", "20", "fc", "b1", "5b", "6a", "cb", "be", "39", "4a", "4c", "58", "cf" },
    {  "d0", "ef", "aa", "fb", "43", "4d", "33", "85", "45", "f9", "02", "7f", "50", "3c", "9f", "a8" },
    {  "51", "a3", "40", "8f", "92", "9d", "38", "f5", "bc", "b6", "da", "21", "10", "ff", "f3", "d2" },
    {  "cd", "0c", "13", "ec", "5f", "97", "44", "17", "c4", "a7", "7e", "3d", "64", "5d", "19", "73" },
    {  "60", "81", "4f", "dc", "22", "2a", "90", "88", "46", "ee", "b8", "14", "de", "5e", "0b", "db" },
    {  "e0", "32", "3a", "0a", "49", "06", "24", "5c", "c2", "d3", "ac", "62", "91", "95", "e4", "79" },
    {  "e7", "c8", "37", "6d", "8d", "d5", "4e", "a9", "6c", "56", "f4", "ea", "65", "7a", "ae", "08" },
    {  "ba", "78", "25", "2e", "1c", "a6", "b4", "c6", "e8", "dd", "74", "1f", "4b", "bd", "8b", "8a" },
    {  "70", "3e", "b5", "66", "48", "03", "f6", "0e", "61", "35", "57", "b9", "86", "c1", "1d", "9e" },
    {  "e1", "f8", "98", "11", "69", "d9", "8e", "94", "9b", "1e", "87", "e9", "ce", "55", "28", "df" },
    {  "8c", "a1", "89", "0d", "bf", "e6", "42", "68", "41", "99", "2d", "0f", "b0", "54", "bb", "16" }
};

        public string[,] substitution_merna_bytes(string[,] input)
        {
            string[,] output = new string[input.GetLength(0), input.GetLength(1)];


            for (int i = 0; i < input.GetLength(0); i++)
            {
                for (int j = 0; j < input.GetLength(1); j++)
                {
                    //extract two characters representing a hexadecimal value.
                    //Convert the first character to a row index
                    //and the second character to a column index using the HexCharToInt method.
                    int row = HexCharToInt(input[i, j][0]);
                    int column = HexCharToInt(input[i, j][1]);

                    output[i, j] = S_Box[row, column];


                }
            }

            return output;
        }

        private int HexCharToInt(char hexChar)
        {
            return int.Parse(hexChar.ToString(), System.Globalization.NumberStyles.HexNumber);
        }





        public string getFromS_Box(char char1, char char2)
        {
            string str = null;

            int i = int.Parse(char1.ToString(), System.Globalization.NumberStyles.HexNumber);
            int j = int.Parse(char2.ToString(), System.Globalization.NumberStyles.HexNumber);

            str = S_Box[i, j];

            return str;
        }

        private string[,] shiftRows(string[,] subPlain2d)
        {
            string[,] shiftPlain2d = new string[4, 4];

            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    //It calculates the new column index by performing a left cyclic shift on the current column 
                    shiftPlain2d[i, j] = subPlain2d[i, (j + i) % 4];
                }
            }

            return shiftPlain2d;
        }


        private string[,] MixColumns(string[,] input)
        {
            // matrix multiplication operation on the state matrix
            string[,] multiply = {
        { "2", "3", "1", "1" },
        { "1", "2", "3", "1" },
        { "1", "1", "2", "3" },
        { "3", "1", "1", "2" }
    };

            string[,] mixColumns = new string[4, 4];
            // binary representation of each element of the input matrix.
            string[,] binary = new string[4, 4];
            string[] arr = new string[4];

            // Convert input to binary
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    //  Converts each hexadecimal digit to its binary representation and stores it in the binary matrix.
                    char char1 = input[i, j][0];
                    char char2 = input[i, j][1];
                    string binary1 = Convert.ToString(Convert.ToInt64(char1.ToString(), 16), 2);
                    string binary2 = Convert.ToString(Convert.ToInt64(char2.ToString(), 16), 2);
                    // each binary string is padded with leading zeros ('0') to ensure that they have a length of 4 characters.
                    binary1 = binary1.PadLeft(4, '0');
                    binary2 = binary2.PadLeft(4, '0');
                    string finalBinary = binary1 + binary2;

                    binary[i, j] = finalBinary;
                }
            }

            //  calculates the new value based on the multiplication matrix and performs the XOR operation as necessary.


            for (int l = 0; l < 4; l++)
            {
                for (int i = 0; i < 4; i++)
                {
                    for (int j = 0; j < 4; j++)
                    {
                        if (multiply[i, j] == "2")
                        {
                            // Shift
                            string num = binary[j, l].Substring(1) + "0";
                            if (binary[j, l][0] == '1')
                            {
                                num = xor(num, "00011011");
                            }
                            arr[j] = num;
                        }
                        else if (multiply[i, j] == "1")
                        {
                            arr[j] = binary[j, l];
                        }
                        else
                        {
                            string num = binary[j, l].Substring(1) + "0";
                            if (binary[j, l][0] == '1')
                            {
                                num = xor(num, "00011011");
                            }
                            num = xor(binary[j, l], num);
                            arr[j] = num;
                        }
                    }
                    //Converts the XOR result back to hexadecimal format and stores it in the mixColumns matrix.
                    mixColumns[i, l] = xor(arr[0], arr[1], arr[2], arr[3]);
                }
            }

            return mixColumns;
        }
        //Performs XOR operation between two binary strings.
        private string xor(string num, string b7)
        {
            string x = "";

            for (int i = 0; i < 8; i++)
            {
                if (num[i] == b7[i])
                    x += '0';
                else
                    x += '1';
            }

            return x;
        }
        //Performs XOR operation between four binary strings, converting the result back to hexadecimal format.
        private string xor(string num1, string num2, string num3, string num4)
        {
            int result = Convert.ToInt32(num1, 2) ^
                         Convert.ToInt32(num2, 2) ^
                         Convert.ToInt32(num3, 2) ^
                         Convert.ToInt32(num4, 2);

            string binaryResult = Convert.ToString(result, 2).PadLeft(8, '0');
            string strHex = Convert.ToInt32(binaryResult, 2).ToString("X2").ToLower();

            return strHex;
        }


        string[] recon_table = { "01", "02", "04", "08", "10", "20", "40", "80", "1b", "36" };
        // Generation key
        private string[,] generate_merna_key(string[,] key, int k)
        {
            string[,] generation = new string[4, 4];
            //rotates the third column of the current round key by one position to the left.
            string[] colum3 = RotateColumn(key);

            //two hexadecimal characters, looks up the corresponding substitution value from the S-Box
            SubstituteColumn(colum3);

            //
            GenerateFirstColumn(generation, key, colum3, k);

            // based on the current round key (key).
            // It performs an XOR operation between each column of the current round key
            // and the corresponding column of the previous round key
            GenerateAllColumns(generation, key);

            return generation;
        }


        // Rotate column 3
        private string[] RotateColumn(string[,] key)
        {
            string[] colum3 = new string[4];

            for (int i = 0; i < 4; i++)
            {
                colum3[i] = key[(i + 1) % 4, 3];
            }

            return colum3;
        }

        // Substitute column using S-Box
        private void SubstituteColumn(string[] column)
        {
            for (int i = 0; i < 4; i++)
            {
                column[i] = getFromS_Box(column[i][0], column[i][1]);
            }
        }
        // Generate first column
        private void GenerateFirstColumn(string[,] generation, string[,] key, string[] colum3, int k)
        {
            for (int i = 0; i < 4; i++)
            {
                //xor m3 awl wa7ed w el arcon ba5od 1 arcon
                string result = XOR(XOR(colum3[i], key[i, 0]), (i == 0) ? recon_table[k] : "00000000");
                generation[i, 0] = result;
            }
        }

        // Generate all columns
        private void GenerateAllColumns(string[,] generation, string[,] key)
        {
            for (int j = 1; j < 4; j++)
            {
                for (int i = 0; i < 4; i++)
                {
                    string result = XOR(generation[i, j - 1], key[i, j]);
                    generation[i, j] = result;
                }
            }
        }


        public static string[,] Add_merna_RoundKey(string[,] state, string[,] roundKey)
        {
            string[,] result = new string[4, 4];

            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    result[i, j] = XOR(state[i, j], roundKey[i, j]);
                }
            }

            return result;
        }
        private static string XOR(string byteState, string byteKey)
        {
            int intState = int.Parse(byteState, System.Globalization.NumberStyles.HexNumber);
            int intKey = int.Parse(byteKey, System.Globalization.NumberStyles.HexNumber);
            int xorResult = intState ^ intKey;
            return xorResult.ToString("x2");
        }



        //done 
        public string[,] ISubBytesColumn(string[,] column)
        {
            string[,] resultingColumn = new string[4, 1];
            int i = 0;
            while (i < 4)
            {
                // Extract hexadecimal value from the current element
                string hexaValue = column[i, 0];
                // Convert the first character to a row index and the second character to a column index
                int row = int.Parse(hexaValue[0].ToString(), System.Globalization.NumberStyles.HexNumber);
                int col = int.Parse(hexaValue[1].ToString(), System.Globalization.NumberStyles.HexNumber);
                // Lookup the value in  S-Box 
                resultingColumn[i, 0] = sBox[row, col];
                i++;
            }
            return resultingColumn;
        }

        //done
        public string[,] CTmatrixGeneration(string CTtext)
        {
            //converting block into state 
            //we divide the string kol harfen m3 b3d , so the new matrix will be half the size of the text
            int m = 0;
            string[] newTextGenerated = new string[CTtext.Length / 2];
            for (int i = 0; i < CTtext.Length; i += 2)
            {
                newTextGenerated[i / 2] = CTtext.Substring(i, 2);
            }
            string[,] CTmat = new string[4, 4];

            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    CTmat[j, i] = newTextGenerated[m];
                    m++;
                }
            }
            return CTmat;
        }
        //done
        public string[,] inverseShiftRows(string[,] CT)
        {
            //1'st row no shifting 
            //2'nd row 1 byte to the right shift
            //3'rd row 2 butes to the right shifting 
            //4ht row 3 bytes to the right shifting
            int i = 0;
            while (i < 4)
            {
                for (int j = 0; j < i; j++)
                {
                    string tempText = CT[i, 3];
                    for (int m = 3; m > 0; m--)
                    {
                        CT[i, m] = CT[i, m - 1];
                    }
                    CT[i, 0] = tempText;
                }
                i++;
            }

            return CT;
        }
        //done 
        public string[,] AddRoundKey(string[,] plainText, string[,] key)
        {
            // Create a new 4x4 matrix to hold the thirdColumn
            string[,] resultext = new string[4, 4];

            // XOR each byte of the plainText matrix with the corresponding byte of the key matrix
            for (int m = 0; m < 4; m++)
            {
                int n = 0;
                while (n < 4)
                {
                    // Convert the byte strings to integers and perform XOR
                    int bytePlain = Convert.ToInt32(plainText[m, n], 16);
                    int byteKey = Convert.ToInt32(key[m, n], 16);
                    int resultingByte = bytePlain ^ byteKey;

                    // Convert the thirdColumn back to a string and store in the thirdColumn matrix
                    resultext[m, n] = resultingByte.ToString("X2");
                    n++;
                }

            }

            // Return the resulting matrix
            return resultext;
        }
        public static int Multiply(int c, int d)
        {
            int b = 0;
            int i = 0;
            while (i < 8)
            {
                if ((d & 1) != 0)
                {
                    b ^= c;
                }

                bool hiBitSet = (c & 0x80) != 0;
                c <<= 1;
                if (hiBitSet)
                {
                    c ^= 0x11b;
                }

                d >>= 1;
                i++;
            }
            return b;
        }
        //done 
        public string[,] generateRoundKeys(string[,] key, string[,] rcon)
        {
            string temp = key[0, 3];
            string[,] temp2 = new string[4, 1];
            string[,] result = new string[4, 4];
            for (int i = 0; i < 4; i++)
            {
                if (i == 0)
                {
                    string[,] thirdColumn = new string[4, 1];
                    string[,] firstColumn = new string[4, 1];
                    for (int j = 0; j < 4; j++)
                    {
                        //copy the last column of the key matrix into temp2
                        temp2[j, 0] = key[j, 3];
                    }
                    for (int j = 0; j < 3; j++)
                    {
                        //rotate the columns of the key matrix.
                        key[j, 3] = key[j + 1, 3];
                    }
                    key[3, 3] = temp;
                    for (int j = 0; j < 4; j++)
                    {
                        thirdColumn[j, 0] = key[j, 3];
                        firstColumn[j, 0] = key[j, i];
                    }
                    //apply the SubBytes to the copied last column.
                    thirdColumn = ISubBytesColumn(thirdColumn);

                    for (int j = 0; j < 4; j++)
                    {
                        // Convert the byte strings to integers and perform XOR
                        int firstByte = Convert.ToInt32(firstColumn[j, 0], 16);
                        int thirdByte = Convert.ToInt32(thirdColumn[j, 0], 16);
                        int r = Convert.ToInt32(rcon[j, rconColumn], 16);
                        int resultByte = firstByte ^ thirdByte ^ r;
                        // Convert the thirdColumn back to a string and store in the thirdColumn matrix
                        result[j, i] = resultByte.ToString("X2");
                    }
                    rconColumn++;
                }
                else
                {
                    string[,] thirdColumn = new string[4, 1];
                    string[,] firstColumn = new string[4, 1];
                    for (int j = 0; j < 4; j++)
                    {
                        if (i != 3)
                        {
                            firstColumn[j, 0] = key[j, i];
                        }
                        else
                        {
                            firstColumn[j, 0] = temp2[j, 0];
                        }
                        thirdColumn[j, 0] = result[j, i - 1];
                        // Convert the byte strings to integers and perform XOR
                        int firstByte = Convert.ToInt32(firstColumn[j, 0], 16);
                        int thirdByte = Convert.ToInt32(thirdColumn[j, 0], 16);
                        int resultByte = firstByte ^ thirdByte;
                        // Convert the thirdColumn back to a string and store in the thirdColumn matrix
                        result[j, i] = resultByte.ToString("X2");
                    }
                }
            }
            for (int j = 0; j < 4; j++)
            {
                key[j, 3] = temp2[j, 0];
            }
            return result;
        }
        //done
        public string[,] inverseSubBytes(string[,] PT)
        {
            string[,] resultText = new string[4, 4];

            for (int m = 0; m < 4; m++)
            {
                for (int n = 0; n < 4; n++)
                {
                    string hexValue = PT[m, n];
                    int row = int.Parse("0" + hexValue[0], System.Globalization.NumberStyles.HexNumber);
                    int col = int.Parse("0" + hexValue[1], System.Globalization.NumberStyles.HexNumber);
                    resultText[m, n] = isBox[row, col];
                }
            }
            return resultText;
        }
        //done 
        public string[,] inverseMixColumns(string[,] mat)
        {

            string[,] res = new string[4, 4];
            int col = 0;
            while (col < 4)
            {
                int[] columnn = new int[4];
                for (int r = 0; r < 4; r++)
                {
                    columnn[r] = Convert.ToInt32(mat[r, col], 16);
                }

                int[] temp1 = new int[4];
                for (int r = 0; r < 4; r++)
                {
                    int dotproduct = 0;
                    for (int i = 0; i < 4; i++)
                    {
                        dotproduct ^= Multiply(invCoefficients[r, i], columnn[i]);
                    }
                    temp1[r] = dotproduct;
                }

                for (int row = 0; row < 4; row++)
                {
                    res[row, col] = temp1[row].ToString("X2");
                }
                col++;
            }

            return res;
        }
    }
}