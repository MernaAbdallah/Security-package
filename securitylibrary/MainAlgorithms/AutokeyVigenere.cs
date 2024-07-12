using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{

    public class AutokeyVigenere : ICryptographicTechnique<string, string>
    {
        char[] englishAlphabet = new char[] { 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 
                                               'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u',
                                               'v', 'w', 'x', 'y', 'z' };
        string word = "";
        public string Analyse(string plainText, string cipherText)
        {
           

            plainText = plainText.ToLower();
            cipherText = cipherText.ToLower();

            //Ki = (Ei - Di + 26) mod 26
            //get the key [after applying the auto method]
            int KL = 0; 
            while(KL < plainText.Length)
            {
                int index1 = Array.IndexOf(englishAlphabet, cipherText[KL]);
                int index2 = Array.IndexOf(englishAlphabet, plainText[KL]);
                int Ki = ((index1 - index2) + 26) % 26;
                word += englishAlphabet[Ki];
                KL++;
            }

            //subtracting the added part from the plain text [following the auto key rule ] if exist
            for (int i = 2; i < word.Length; i++)  
            {
                for (int j = 3; j < word.Length; j++) 
                {
                    string temp = word.Substring(i, j);
                    if (plainText.Contains(temp))
                    {
                        return word.Substring(0, i);
                    }
                    else
                    {
                        break;
                    }
                }
            }

            return word;
            //throw new NotImplementedException();
        }

        public string Decrypt(string cipherText, string key)
        {
            cipherText = cipherText.ToLower();
            int textIdx = -1;  // index of last char added to PT
            int keyIdx = -1; // index of last char added to key

            do
            {
                //formula Di = (Ei - Ki + 26) mod 26 
                for (int i = textIdx + 1; i < key.Length; i++)
                {
                    int index1 = Array.IndexOf(englishAlphabet, cipherText[i]);
                    int index2 = Array.IndexOf(englishAlphabet, key[i]);
                    int Di = ((index1 - index2) + 26) % 26;
                    word += englishAlphabet[Di];
                    textIdx = i; 
                }

                // breaking the while loop when key  = ct
                if (cipherText.Length == key.Length)
                {
                    break;
                }

                // making the key an dthe PT the same lenght                             
                for (int i = keyIdx + 1; i < word.Length; i++)
                {
                    if (key.Length == cipherText.Length) break;
                    key += word[i];
                    keyIdx = i;  
                }
            }
            while (true);

            return word;



            //throw new NotImplementedException();
        }
        public string Encrypt(string plainText, string key)
        {
            // make the key and the PT  the same lenght 
            int counter = 0; 
            if(key.Length != plainText.Length)
            {
                while(key.Length != plainText.Length)
                {
                    key += plainText[counter];
                    counter++;
                }
            }
     
            int lenght = plainText.Length;
            int PTL = 0; 
            while(PTL < lenght)
            {
                // formula Ei = (Pi + Ki) mod 26
                int index1 = Array.IndexOf(englishAlphabet, plainText[PTL]);
                int index2 = Array.IndexOf(englishAlphabet, key[PTL]);
                int Ei = (index1 + index2) % 26;
                word += englishAlphabet[Ei];
                PTL++;
            }
            return word;

            //throw new NotImplementedException();
        }
    }
}
