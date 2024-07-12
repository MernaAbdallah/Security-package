using System;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.DiffieHellman
{
    public class DiffieHellman
    {
        public List<int> GetKeys(int q, int alpha, int xa, int xb)
        {
            BigInteger Ya = BigInteger.ModPow(alpha, xa, q);
            BigInteger Yb = BigInteger.ModPow(alpha, xb, q);
            BigInteger Ka = BigInteger.ModPow(Yb, xa, q);
            BigInteger Kb = BigInteger.ModPow(Ya, xb, q);

            int KA = (int)(Ka);
            int KB = (int)(Kb);
            return new List<int> { KA, KB };
        }
    }
}
