using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Ceaser : ICryptographicTechnique<string, int>
    {
        char[] englishAlphabet = new char[] { 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 
                                                'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 
                                                'v', 'w', 'x', 'y', 'z' };
        string word = "";
        int PT = 0, CT = 0;

        public string Encrypt(string plainText, int key)
        {
            int PTlenght = plainText.Length;
            int k = key;
            for(int i= 0; i< PTlenght; i++)
            {
                int j = 0;
                while (j < 26)
                {
                    if (plainText[i] == englishAlphabet[j])
                    {
                        word += englishAlphabet[(j + k) % 26];
                    }
                    j++;
                }
            }
            return word;
        }

        public string Decrypt(string cipherText, int key)
        {
            cipherText = cipherText.ToLower();
            
            for (int i = 0; i < cipherText.Length; i++)
            {
                int j = 0;
                while (j < 26)
                {
                    if (englishAlphabet[j] == cipherText[i])
                    {
                        //if the key > index of  j , we get -ve num so
                        //we add 26 until we get to the first +ve num
                        int k = j;
                        if (j < key)
                        {
                            k = j + 26;
                        }
                        word += englishAlphabet[k - key];
                       
                    }
                    j++;
                }
            }
            return word;
        }

        //get the key
        public int Analyse(string plainText, string cipherText)
        {
            cipherText = cipherText.ToLower();
           
            int count = 0; 
            while (count < 26)
            {
                if (plainText[0] == englishAlphabet[count])
                {
                    PT = count;
                }
                if (cipherText[0] == englishAlphabet[count])
                {
                    CT = count;
                }
                count++;
            }
            int key = CT - PT;
            if (key < 0)
            {
                key += 26;
            }
            return key;
        }
    }
}
