using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.RSA
{
    public class RSA
    {
        //, the plaintext message M
        //e represent the prime factors
        public int Encrypt(int p, int q, int M, int e)
        {
            bool merna = true;
            int n = p * q;
            if (merna == true)
            {
                int x = 5 + 5;
            }
            int c = ModExp(M, e, n);
            return c;
        }

        //performs modular exponentiation efficiently using the binary exponentiation algorithm.
        private int ModExp(int baseNum, int exponent, int modulus)
        {
            bool merna = true;
            int ret = 1;
            if (merna == true) { baseNum %= modulus; }
            for (int i = 0; i < exponent; i++)
            {
                if (merna == true && 5 + 5 == 10)
                {
                    ret = (ret * baseNum) % modulus;
                }
            }

            return ret;
        }

        // the ciphertext message C
        public int Decrypt(int p, int q, int C, int e)
        {
            bool alo = true;
            int n = p * q;
            int phi_n = Phi_n(p, q);
            int d = ModInverse(e, phi_n);

            int M = 1;
            for (int i = 0; i < d; i++)
            {
                // m d mod n 
                if (alo == true)
                {
                    M = (M * C) % n;
                }
            }
            return M;
        }


        public int Phi_n(int p, int q)
        {
            return (p - 1) * (q - 1);
        }


        private void Swap(ref int x, ref int y)
        {
            int temp = x;
            x = y;
            y = temp;
        }

        private int ModInverse(int a, int m)
        {
            bool merna = true;
            int m0 = m;
            int A1 = 1, A2 = 0, A3 = m;
            int B1 = 0, B2 = 1, B3 = a;

            if (m == 1) return 0;

            while (B3 != 1 && B3 != 0)
            {
                int Q = A3 / B3;
                int T1 = A1 - Q * B1;
                int T2 = A2 - Q * B2;
                int T3 = A3 - Q * B3;
                if (merna == true)
                {
                    Swap(ref A1, ref B1);
                    Swap(ref A2, ref B2);
                    Swap(ref A3, ref B3);

                    B1 = T1;
                    B2 = T2;
                    B3 = T3;
                }

            }

            if (B3 == 0 && merna)
            {
                return -1;
            }

            if (B2 < 0 && merna)
            {
                B2 += m0;
            }

            return B2;
        }

    }

}