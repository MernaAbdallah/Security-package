using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class RailFence : ICryptographicTechnique<string, int>
    {
        public int Analyse(string plainText, string cipherText)
        {
            Console.WriteLine("Real Plain Text : " + plainText);
            Console.WriteLine(">_<");

            int key = 0;
            string Guessed_plainText;

            do
            {
                key++;
                Guessed_plainText = Decrypt(cipherText, key);
                Console.WriteLine(key);
                Console.WriteLine(">_<");

                if (plainText.Count() < Guessed_plainText.Count())
                {
                    List<char> temp = Tokenize(Guessed_plainText);
                    temp.RemoveRange(plainText.Count(), Guessed_plainText.Count() - plainText.Count());
                    Guessed_plainText = new string(temp.ToArray());
                }

                //if (key == (cipherText.Count() / 2))
                //{
                //    break;
                //}
            }
            while (Guessed_plainText.ToUpper() != plainText.ToUpper());

            return key;
        }

        public string Decrypt(string cipherText, int key)
        {
            List<char> cipher_text = Tokenize(cipherText);
            int column_size = cipher_text.Count / key;
            int number_of_columns_increased = cipher_text.Count % key;

            List<char> plain_text = new List<char>();

            for (int i = 0; i < column_size; i++)
            {
                int k = 0;
                for (int j = 0; j < key; j++)
                {
                    if (k <= number_of_columns_increased)
                    {
                        plain_text.Add(cipher_text[i + (j * (column_size + 1))]);
                        k++;
                    }
                    else
                    {
                        plain_text.Add(cipher_text[i + (j * column_size) + number_of_columns_increased]);
                    }
                }
            }

            if (number_of_columns_increased > 0)
            {
                for (int j = 0; j < number_of_columns_increased; j++)
                {
                    plain_text.Add(cipher_text[column_size + (j * (column_size + 1))]);
                }
            }

            string plainString = new string(plain_text.ToArray());
            Console.WriteLine("Plain Text : " + plainString);

            return plainString;
        }

        public string Encrypt(string plainText, int key)
        {
            List<char> plain_text = Tokenize(plainText);
            int column_size = plain_text.Count / key;
            int number_of_columns_increased = plain_text.Count % key;

            List<char> cipher_text = new List<char>();

            for (int i = 0; i < key; i++)
            {
                for (int j = 0; j < column_size; j++)
                {
                    cipher_text.Add(plain_text[i + (j * key)]);
                }

                if (i < number_of_columns_increased)
                {
                    cipher_text.Add(plain_text[i + (column_size * key)]);
                }
            }

            // Convert the List<char> to a string and then print it
            string cipherString = new string(cipher_text.ToArray());
            Console.WriteLine("Cipher Text : " + cipherString);

            return cipherString;
        }

        public List<char> Tokenize(string Text)
        {
            List<char> letters_in_string = new List<char>();

            foreach (char c in Text)
            {
                if (char.IsLetter(c))
                {
                    letters_in_string.Add(c);
                }
            }

            return letters_in_string;
        }

    }
}
