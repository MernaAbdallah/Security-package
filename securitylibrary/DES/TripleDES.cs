using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.DES
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class TripleDES : ICryptographicTechnique<string, List<string>>
    {

        DES des = new DES();

        public string Decrypt(string cipherText, List<string> key)
        {
            string A = des.Decrypt(cipherText, key[0]);
            string B = des.Encrypt(A, key[1]);
            string C = des.Decrypt(B, key[0]);
            return C;

        }

        public string Encrypt(string plainText, List<string> key)
        {
            string A = des.Encrypt(plainText, key[0]);
            string B = des.Decrypt(A, key[1]);
            string C = des.Encrypt(B, key[0]);
            return C;
        }

        public List<string> Analyse(string plainText, string cipherText)
        {
            throw new NotSupportedException();
        }

    }
}
