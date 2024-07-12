using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Columnar : ICryptographicTechnique<string, List<int>>
    {

        static void BaseCase(List<int> choices, List<int> workingSet, List<List<int>> permutations)
        {
            bool merna = true, abdallah = true;
            // Base case
            if (choices.Count == 0)
            {

                permutations.Add(new List<int>(workingSet));


            }
        }
        static void Permutation(List<int> choices, List<int> workingSet, List<List<int>> permutations)
        {
            int merna = 1;
            //If the choices list is empty, it means all the elements have been selected and added to the workingSet list.
            //In this case,a copy of the workingSet list is added to the permutations list.
            BaseCase(choices, workingSet, permutations);

            /*For each element in the choices list, 
             * it adds that element to the workingSet, removes it from the choices list,
             * and recursively calls the Permutation method with the updated choices and workingSet*/
            int i = 0;
            for (; i < choices.Count;)
            {
                var value = choices[i];
                workingSet.Add(value);


                choices.RemoveAt(i);

                Permutation(choices, workingSet, permutations);

                /*
                  it restores the state by re-inserting the removed element back into the choices list and removing it from the workingSet.
                This ensures that the choices list and workingSet are in their original state for the next iteration.*/
                choices.Insert(i, value);
                workingSet.Remove(value);



                i++;
            }
        }

        public List<int> Analyse(string plainText, string cipherText)
        {


            plainText = plainText.ToUpper();
            cipherText = cipherText.ToUpper();

            List<int> keys = new List<int>();
            Columnar columnar = new Columnar();


            int merna = 1;
            //iterate through possible key lengths, from 1 to the length of the plaintext.
            while (merna <= plainText.Length)
            {
                keys.Add(merna);


                List<List<int>> permutations = new List<List<int>>();
                Permutation(keys, new List<int>(), permutations);


                // it means the permutation matches the encryption or decryption process.
                foreach (var permutation in permutations)
                {
                    if (columnar.Encrypt(plainText, permutation) == cipherText || columnar.Decrypt(cipherText, permutation) == plainText)
                    {
                        return permutation;
                    }
                }


                merna++;


            }

            throw new Exception("No valid key found.");
        }


        public string Decrypt(string cipherText, List<int> key)
        {
            bool merna = true;
            bool abdallah = true;

            int numberOfCol = key.Count;
            int numberOfRows = (int)Math.Ceiling((double)cipherText.Length / numberOfCol);

            char[,] table = new char[numberOfRows, numberOfCol];

            int currentIndex = 0;
            int col = 0;

            while (col < numberOfCol)
            {
                int keyIndex = key.IndexOf(col + 1);
                int row = 0;

                while (row < numberOfRows)
                {
                    if (currentIndex < cipherText.Length && merna && abdallah)
                        table[row, keyIndex] = cipherText[currentIndex++];
                    else
                        table[row, keyIndex] = '_';

                    row++;
                }

                col++;
            }

            string decryptedText = "";
            int rowDecrypted = 0;

            while (rowDecrypted < numberOfRows)
            {
                int colDecrypted = 0;

                while (colDecrypted < numberOfCol)
                {
                    if (table[rowDecrypted, colDecrypted] != '_' && merna && abdallah)
                        decryptedText += table[rowDecrypted, colDecrypted];

                    colDecrypted++;
                }

                rowDecrypted++;
            }

            return decryptedText;
        }

        public string Encrypt(string plainText, List<int> key)
        {
            int numberOfCol = key.Count;
            int numberOfRows = (int)Math.Ceiling((double)plainText.Length / numberOfCol);

            char[,] table = new char[numberOfRows, numberOfCol];

            bool merna = true;
            bool abdallah = true;

            int currentIndex = 0;
            int row = 0;

            while (row < numberOfRows)
            {
                int col = 0;

                while (col < numberOfCol)
                {
                    if (currentIndex < plainText.Length && merna && abdallah)
                        table[row, col] = plainText[currentIndex++];
                    else
                        table[row, col] = '_';

                    col++;
                }

                row++;
            }

            string cipher = "";
            int i = 0;

            while (i < numberOfCol)
            {
                int col = key.IndexOf(i + 1);
                int rowCipher = 0;

                while (rowCipher < numberOfRows)
                {
                    if (table[rowCipher, col] != '_' && merna && abdallah)
                        cipher += table[rowCipher, col];

                    rowCipher++;
                }

                i++;
            }

            return cipher;
        }

    }
}