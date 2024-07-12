using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using static System.Net.Mime.MediaTypeNames;

namespace SecurityLibrary
{
    public class Monoalphabetic : ICryptographicTechnique<string, string>
    {
        char[] englishAlphabet = new char[] { 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h','i', 'j', 'k', 'l', 'm',
                                            'n', 'o', 'p', 'q', 'r', 's', 't', 'u',
                                                'v', 'w', 'x', 'y', 'z' };
        string word = "";

        public string Analyse(string plainText, string cipherText)
        {
            cipherText = cipherText.ToLower();
            string notExsisInCT = "";
            int notExsisInCTindex = 0;
           
            //handling if the ct missing letters
            for(int i =0; i<englishAlphabet.Length; i++)
            {
                if (!cipherText.Contains(englishAlphabet[i])){

                    notExsisInCT += englishAlphabet[i];
                }
            }

           
            for(int  i =0; i<englishAlphabet.Length; i++)
            {
                bool letterIsFound = false;
                int letterIndex = -1;

                for (int j = 0; j < plainText.Length; j++)
                {
                    if (plainText[j] == englishAlphabet[i])
                    {
                        letterIsFound = true;
                        letterIndex = j;
                    }
                }    

                if (letterIsFound)
                {
                   word += cipherText[letterIndex];

                }
                else
                {
                    word += notExsisInCT[notExsisInCTindex];
                    notExsisInCTindex++;
                }
            }
            
            return word;
            //throw new NotImplementedException();
        }

        public string Decrypt(string cipherText, string key)
        {
            cipherText = cipherText.ToLower();
            for (int i = 0; i < cipherText.Length; i++)
            {
                for (int j = 0; j < englishAlphabet.Length; j++)
                {
                    if (cipherText[i] == key[j])
                    {
                        word += englishAlphabet[j];
                    }
                }
            }
            return word;
            //throw new NotImplementedException();
        }

        public string Encrypt(string plainText, string key)
        {
            //note: el key metrateb bel index
            //y3ne el is index 5 in alphapet  fa hnbos 3la index 5 fe el key
            for (int i = 0; i<plainText.Length; i++)
            {
                for (int j= 0; j<englishAlphabet.Length; j++)
                {
                    if (plainText[i] == englishAlphabet[j])
                    {
                        word += key[j];
                    }
                }
            }
            return word;
            //throw new NotImplementedException();
        }

        /// <summary>
        /// Frequency Information:
        /// E   12.51%
        /// T	9.25
        /// A	8.04
        /// O	7.60
        /// I	7.26
        /// N	7.09
        /// S	6.54
        /// R	6.12
        /// H	5.49
        /// L	4.14
        /// D	3.99
        /// C	3.06
        /// U	2.71
        /// M	2.53
        /// F	2.30
        /// P	2.00
        /// G	1.96
        /// W	1.92
        /// Y	1.73
        /// B	1.54
        /// V	0.99
        /// K	0.67
        /// X	0.19
        /// J	0.16
        /// Q	0.11
        /// Z	0.09
        /// </summary>
        /// <param name="cipher"></param>
        /// <returns>Plain text</returns>
        public string AnalyseUsingCharFrequency(string cipher)
        {
            cipher = cipher.ToLower();
            string freq = "zqjxkvbywgpfmucdlhrsnioate";
            int[] arr = new int[26];
            int counter;

            for(int  i = 0; i<englishAlphabet.Length; i++)
            {
                int count = 0;
                for(int j =0; j<cipher.Length; j++)
                {
                    if (cipher[j] == englishAlphabet[i])
                    {
                        count++;
                    }
                }
                arr[i] = count;
            }

            //sort the array of the letters of the cipher text
            for (int i = 0; i < arr.Length - 1; i++)
            {
                int minIndex = i;
                for (int j = i + 1; j < arr.Length; j++)
                {
                    if (arr[j] < arr[minIndex])
                    {
                        minIndex = j;
                    }
                }
                if (minIndex != i)
                {
                    // Swap the elements in arr
                    int temp = arr[i];
                    arr[i] = arr[minIndex];
                    arr[minIndex] = temp;

                    // Swap the corresponding elements in englishAlphabet
                    char t = englishAlphabet[i];
                    englishAlphabet[i] = englishAlphabet[minIndex];
                    englishAlphabet[minIndex] = t;
                }
            }

            string key = "";
            for (int i = 0; i < englishAlphabet.Length; i++)
            {
                key += englishAlphabet[i];
            }
            for (int i = 0; i < cipher.Length; i++)
            {
                int index = key.IndexOf(cipher[i]);
                word += freq[index];
            }
            return word;


        }
    }
}
