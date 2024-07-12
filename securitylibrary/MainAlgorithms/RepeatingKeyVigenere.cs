using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class RepeatingkeyVigenere : ICryptographicTechnique<string, string>
    {
        char[] englishAlphabet = new char[] { 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j',
                                                'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 
                                                'v', 'w', 'x', 'y', 'z' };
        string word = "";
        public string Analyse(string plainText, string cipherText)
        {
            plainText = plainText.ToLower();
            cipherText = cipherText.ToLower();

            //Ki = (Ei - Di + 26) mod 26
            //get the key [after applying the auto method]
            int i = 0;
            while(i< plainText.Length)
            {
                int index1 = Array.IndexOf(englishAlphabet, cipherText[i]);
                int index2 = Array.IndexOf(englishAlphabet, plainText[i]);
                int Ki = ((index1 - index2) + 26) % 26;
                word += englishAlphabet[Ki];
                i++;
            }


            // Find the original key by comparing substrings
            int length = 1;
            while (length < word.Length)
            {
                // Extract a substring from the beginning of the word with a specific length
                string temp = word.Substring(0, length);

                // Check if the substring is equal to a subsequent substring of the same length
                if (String.Equals(temp, word.Substring(length, length)))
                {

                    word = temp;
                    // key is found
                    break;
                }
                
                length++;
            }
            return word;
            // throw new NotImplementedException();
        }

        public string Decrypt(string cipherText, string key)
        {
            //make the key and the CT of the same length
            cipherText = cipherText.ToLower();
            if (key.Length != cipherText.Length)
            {
                int counter = 0;
                while (key.Length != cipherText.Length)
                {
                    key += key[counter];
                    counter++;
                }
            }
            

            int CTL = 0;
            while(CTL < cipherText.Length)
            {
                //formula Di = (Ei - Ki + 26) mod 26 
                int index1 = Array.IndexOf(englishAlphabet, cipherText[CTL]);
                int index2 = Array.IndexOf(englishAlphabet, key[CTL]);
                int Di = ((index1 - index2) + 26) % 26;
                word += englishAlphabet[Di];

                CTL++;
            } 
            return word;
            //throw new NotImplementedException();
        }

        public string Encrypt(string plainText, string key)
        {
            //make the key and the PT of the same length 
            if(key.Length != plainText.Length)
            {
                int counter = 0;
                while(key.Length != plainText.Length)
                {
                    key += key[counter];
                    counter++;
                }
            }

            int PTL = 0;
            while (PTL < plainText.Length)
            {

                //formula Ei = (Ei + Ki) mod 26
                int index1 = Array.IndexOf(englishAlphabet, plainText[PTL]);
                int index2 = Array.IndexOf(englishAlphabet, key[PTL]);
                int Ei = (index1 + index2) % 26;
                word += englishAlphabet[Ei];
                PTL++;
            }
            return word;
           // throw new NotImplementedException();
        }
    }
}