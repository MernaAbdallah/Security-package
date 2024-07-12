using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class PlayFair : ICryptographicTechnique<string, string>
    {
        public string Analyse(string plainText)
        {
            throw new NotImplementedException();
        }

        public string Analyse(string plainText, string cipherText)
        {
            throw new NotSupportedException();
        }

        public string Decrypt(string cipherText, string key)
        {
            char[,] matrix = GenerateMatrix(key);
            List<string> diagrams = SplitTextToDiagrams(cipherText.ToLower());
            StringBuilder decryptedText = new StringBuilder();

            foreach (string diagram in diagrams)
            {
                char firstLetter = diagram[0];
                char secondLetter = diagram.Length > 1 ? diagram[1] : 'x';

                int[] firstIndex = GetLetterIndex(matrix, firstLetter);
                int[] secondIndex = GetLetterIndex(matrix, secondLetter);

                if (firstIndex[1] == secondIndex[1])
                {
                    decryptedText.Append(matrix[(firstIndex[0] - 1 + 5) % 5, firstIndex[1]]);
                    decryptedText.Append(matrix[(secondIndex[0] - 1 + 5) % 5, secondIndex[1]]);
                }
                else if (firstIndex[0] == secondIndex[0])
                {
                    decryptedText.Append(matrix[firstIndex[0], (firstIndex[1] - 1 + 5) % 5]);
                    decryptedText.Append(matrix[secondIndex[0], (secondIndex[1] - 1 + 5) % 5]);
                }
                else
                {
                    decryptedText.Append(matrix[firstIndex[0], secondIndex[1]]);
                    decryptedText.Append(matrix[secondIndex[0], firstIndex[1]]);
                }
            }

            for (int i = 1; i < decryptedText.Length - 1; i += 2)
            {
                if ((decryptedText[i] == 'x' || decryptedText[i] == 'X') && decryptedText[i - 1] == decryptedText[i + 1])
                {
                    decryptedText.Remove(i, 1);
                    i--;
                }
            }

            if (decryptedText.Length > 0 && (decryptedText[decryptedText.Length - 1] == 'x' || decryptedText[decryptedText.Length - 1] == 'X'))
            {
                if (decryptedText.Length > 1 && decryptedText[decryptedText.Length - 2] == decryptedText[decryptedText.Length - 1])
                {
                    decryptedText.Remove(decryptedText.Length - 1, 1);
                }
                else
                {
                    decryptedText.Remove(decryptedText.Length - 1, 1);
                }
            }

            return decryptedText.ToString().ToLower();
        }



        public string Encrypt(string plainText, string key)
        {
            char[,] matrix = GenerateMatrix(key);
            List<string> diagrams = SplitTextToDiagrams(plainText.ToLower());
            List<string> modifiedDiagrams = new List<string>();

            foreach (string diagram in diagrams)
            {
                char firstLetter = diagram[0];

                if (diagram.Length > 1 && firstLetter == diagram[1])
                {
                    modifiedDiagrams.Add(firstLetter.ToString());
                    modifiedDiagrams.Add('x'.ToString());
                }
                else
                {
                    modifiedDiagrams.Add(diagram);
                }
            }

            StringBuilder encryptedText = new StringBuilder();

            foreach (string diagram in modifiedDiagrams)
            {
                char firstLetter = diagram[0];
                char secondLetter = diagram.Length > 1 ? diagram[1] : 'x';

                int[] firstIndex = GetLetterIndex(matrix, firstLetter);
                int[] secondIndex = GetLetterIndex(matrix, secondLetter);

                if (firstIndex[1] == secondIndex[1])
                {
                    encryptedText.Append(matrix[(firstIndex[0] + 1) % 5, firstIndex[1]]);
                    encryptedText.Append(matrix[(secondIndex[0] + 1) % 5, secondIndex[1]]);
                }
                else if (firstIndex[0] == secondIndex[0])
                {
                    encryptedText.Append(matrix[firstIndex[0], (firstIndex[1] + 1) % 5]);
                    encryptedText.Append(matrix[secondIndex[0], (secondIndex[1] + 1) % 5]);
                }
                else
                {
                    encryptedText.Append(matrix[firstIndex[0], secondIndex[1]]);
                    encryptedText.Append(matrix[secondIndex[0], firstIndex[1]]);
                }
            }

            return encryptedText.ToString().ToUpper();
        }

        static private char[,] GenerateMatrix(string key)
        {
            key = RemoveDuplicates(key.ToLower());

            string keyAlphabet = key;

            string alphabet = "abcdefghiklmnopqrstuvwxyz";

            alphabet = alphabet.Replace("j", "");

            keyAlphabet += alphabet;

            char[,] matrix = new char[5, 5];
            HashSet<char> usedLetters = new HashSet<char>();

            int index = 0;
            for (int i = 0; i < 5; i++)
            {
                for (int j = 0; j < 5; j++)
                {
                    while (usedLetters.Contains(keyAlphabet[index]))
                    {
                        index++;
                    }

                    matrix[i, j] = keyAlphabet[index];
                    usedLetters.Add(keyAlphabet[index]);
                    index++;
                }
            }

            return matrix;
        }

        static private string RemoveDuplicates(string key)
        {
            HashSet<char> uniqueChars = new HashSet<char>(key);
            return string.Concat(uniqueChars);
        }

        static private List<string> SplitTextToDiagrams(string plainText)
        {
            List<string> diagrams = new List<string>();
            int currentIndex = 0;

            while (currentIndex < plainText.Length)
            {
                if (currentIndex == plainText.Length - 1)
                {
                    diagrams.Add(plainText[currentIndex] + "x");
                    break;
                }

                char currentChar = plainText[currentIndex];
                char nextChar = plainText[currentIndex + 1];

                if (currentChar == nextChar)
                {
                    diagrams.Add(currentChar + "x");
                    currentIndex++;
                }
                else
                {
                    diagrams.Add(plainText.Substring(currentIndex, 2));
                    currentIndex += 2;
                }
            }

            return diagrams;
        }


        static private int[] GetLetterIndex(char[,] matrix, char letter)
        {
            int[] index = new int[2];

            for (int i = 0; i < 5; i++)
            {
                for (int j = 0; j < 5; j++)
                {
                    if ((matrix[i, j] == 'i' || matrix[i, j] == 'j') && (letter == 'i' || letter == 'j'))
                    {
                        index[0] = i;
                        index[1] = j;
                        return index;
                    }
                    else if (matrix[i, j] == letter)
                    {
                        index[0] = i;
                        index[1] = j;
                        return index;
                    }
                }
            }

            return index;
        }
    }
}