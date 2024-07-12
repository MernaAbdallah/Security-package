using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    /// <summary>
    /// The List<int> is row based. Which means that the key is given in row based manner.
    /// </summary>
    public class HillCipher : ICryptographicTechnique<string, string>, ICryptographicTechnique<List<int>, List<int>>
    {
        private static Dictionary<char, int> letterIndexMap = new Dictionary<char, int>
        {
            {'a', 0}, {'b', 1}, {'c', 2}, {'d', 3}, {'e', 4}, {'f', 5},
            {'g', 6}, {'h', 7}, {'i', 8}, {'j', 9}, {'k', 10}, {'l', 11},
            {'m', 12}, {'n', 13}, {'o', 14}, {'p', 15}, {'q', 16}, {'r', 17},
            {'s', 18}, {'t', 19}, {'u', 20}, {'v', 21}, {'w', 22}, {'x', 23},
            {'y', 24}, {'z', 25}
        };

        static void TransposeMatrix(List<int> matrix)
        {
            Swap(matrix, 1, 3);
            Swap(matrix, 2, 6);
            Swap(matrix, 5, 7);
        }

        static void Swap(List<int> matrix, int i, int j)
        {
            int temp = matrix[i];
            matrix[i] = matrix[j];
            matrix[j] = temp;
        }

        public List<int> ConvertToIndices(string plainText)
        {
            return plainText.Select(c => letterIndexMap[char.ToLower(c)]).ToList();
        }

        public List<int> Encrypt(List<int> plainText, List<int> key)
        {
            int root = 0, PT_index = 0, sum = 0;

            if (key.Count() == 4)
                root = 2;
            else if (key.Count() == 9)
                root = 3;

            List<int> result = new List<int>();
            List<int> vec = new List<int>();

            for (int i = 0; i < plainText.Count(); i += root)
            {

                for (int j = 0; j < root; j++)
                {
                    vec.Add(plainText[PT_index]);
                    PT_index++;
                }

                for (int k = 0; k < key.Count(); k += root)
                {
                    for (int l = 0; l < root; l++)
                    {
                        sum += key[k + l] * vec[l];
                    }
                    result.Add(sum % 26);
                    sum = 0;
                }
                vec.Clear();
            }

            return result;
        }

        public string Encrypt(string plainText, string key)
        {
            int root = 0;
            if (key.Length == 4)
                root = 2;
            else if (key.Length == 9)
                root = 3;

            List<int> result = new List<int>();
            List<int> vec = new List<int>();

            List<int> plainTextIndices = ConvertToIndices(plainText);

            for (int i = 0; i < plainTextIndices.Count; i += root)
            {
                for (int j = 0; j < root; j++)
                {
                    vec.Add(plainTextIndices[i + j]);
                }

                for (int k = 0; k < key.Length; k += root)
                {
                    int sum = 0;
                    for (int l = 0; l < root; l++)
                    {
                        sum += letterIndexMap[key[k + l]] * vec[l];
                    }
                    result.Add((sum % 26 + 26) % 26);
                }
                vec.Clear();
            }

            StringBuilder encryptedText = new StringBuilder();
            foreach (int value in result)
            {
                char encryptedChar = letterIndexMap.First(x => x.Value == value).Key;
                encryptedText.Append(encryptedChar);
            }
            Console.WriteLine(encryptedText.ToString());

            return encryptedText.ToString();
        }

        public List<int> Decrypt(List<int> cipherText, List<int> key)
        {
            int det = 0, pos_int = 0, x = 0;

            List<int> res = new List<int>();

            for (int i = 0; i < key.Count; ++i)
            {
                if (key[i] >= 0 || key[i] <= 25)
                    continue;
                else
                    throw new NotImplementedException();
            }

            if (key.Count == 4)
            {
                det = (key[0] * key[3]) - (key[1] * key[2]);

                while (det < 0)
                    det += 26;

                det = det % 26;

                int f = 26, n = det;
                while (n != 0)
                {
                    int t = f % n;
                    f = n;
                    n = t;

                }
                if (f != 1)
                    throw new NotImplementedException();

                int inv = 1 / ((key[0] * key[3]) - (key[1] * key[2]));

                x = inv * key[3];
                while (x < 0)
                {
                    x += 26;
                }
                x = x % 26;
                res.Add(x);

                x = key[1] * inv * -1;
                while (x < 0)
                {
                    x += 26;
                }
                x = x % 26;
                res.Add(x);

                x = key[2] * inv * -1;
                while (x < 0)
                {
                    x += 26;
                }
                x = x % 26;
                res.Add(x);

                x = inv * key[0];
                while (x < 0)
                {
                    x += 26;
                }
                x = x % 26;
                res.Add(x);
            }

            if (key.Count == 9)
            {
                det = ((key[0]) * ((key[4]) * (key[8]) - (key[5] * key[7]))) -
                      ((key[1]) * ((key[3]) * (key[8]) - (key[5] * key[6]))) +
                      ((key[2]) * ((key[3]) * (key[7]) - (key[4] * key[6])));

                while (det < 0)
                    det += 26;

                det = det % 26;

                int f = 26, n = det;
                while (n != 0)
                {
                    int t = f % n;
                    f = n;
                    n = t;

                }
                if (f != 1)
                    throw new NotImplementedException();



                for (int i = 1; i < 26; ++i)
                {
                    if ((i * det) % 26 == 1)
                    {
                        pos_int = i;
                        break;
                    }
                }

                //k00
                x = (key[4] * key[8]) - (key[5] * key[7]);
                while (x < 0)
                    x += 26;
                if (x >= 26)
                {
                    x = x % 26;
                }

                res.Add((pos_int * x) % 26);
                while (res[0] < 0)
                    res[0] += 26;

                res[0] = res[0] % 26;
                //k01
                x = (key[3] * key[8]) - (key[5] * key[6]);
                while (x < 0)
                    x += 26;
                if (x >= 26)
                {
                    x = x % 26;
                }

                res.Add((pos_int * -1 * x) % 26);
                while (res[1] < 0)
                    res[1] += 26;

                res[1] = res[1] % 26;
                //k02
                x = (key[3] * key[7]) - (key[4] * key[6]);
                while (x < 0)
                    x += 26;
                if (x >= 26)
                {
                    x = x % 26;
                }

                res.Add((pos_int * x) % 26);
                while (res[2] < 0)
                    res[2] += 26;

                res[2] = res[2] % 26;
                //k10
                x = (key[1] * key[8]) - (key[2] * key[7]);
                while (x < 0)
                    x += 26;
                if (x >= 26)
                {
                    x = x % 26;
                }

                res.Add((pos_int * -1 * x) % 26);
                while (res[3] < 0)

                    res[3] += 26;

                res[3] = res[3] % 26;
                //k11
                x = (key[0] * key[8]) - (key[2] * key[6]);
                while (x < 0)
                    x += 26;
                if (x >= 26)
                {
                    x = x % 26;
                }

                res.Add((pos_int * x) % 26);
                while (res[4] < 0)
                    res[4] += 26;

                res[4] = res[4] % 26;
                //k12
                x = (key[0] * key[7]) - (key[1] * key[6]);
                while (x < 0)
                    x += 26;
                if (x >= 26)
                {
                    x = x % 26;
                }

                res.Add((pos_int * -1 * x) % 26);
                while (res[5] < 0)
                    res[5] += 26;

                res[5] = res[5] % 26;
                //k20
                x = (key[1] * key[5]) - (key[2] * key[4]);
                while (x < 0)
                    x += 26;
                if (x >= 26)
                {
                    x = x % 26;
                }

                res.Add((pos_int * x) % 26);
                while (res[6] < 0)
                    res[6] += 26;

                res[6] = res[6] % 26;
                //k21
                x = (key[0] * key[5]) - (key[2] * key[3]);
                while (x < 0)
                    x += 26;
                if (x >= 26)
                {
                    x = x % 26;
                }

                res.Add((pos_int * -1 * x) % 26);
                while (res[7] < 0)
                    res[7] += 26;

                res[7] = res[7] % 26;
                //k22
                x = (key[0] * key[4]) - (key[1] * key[3]);
                while (x < 0)
                    x += 26;
                if (x >= 26)
                {
                    x = x % 26;
                }

                res.Add((pos_int * x) % 26);
                while (res[8] < 0)
                    res[8] += 26;

                res[8] = res[8] % 26;

                for (int i = 0; i < res.Count(); i++)
                {
                    Console.WriteLine(res[i]);
                }

                TransposeMatrix(res);
            }

            return Encrypt(cipherText, res);
        }

        public string Decrypt(string cipherText, string key)
        {
            List<int> cipherTextIndices = ConvertToIndices(cipherText);
            List<int> keyTextIndices = ConvertToIndices(key);

            List<int> result = Decrypt(cipherTextIndices, keyTextIndices);

            StringBuilder plainText = new StringBuilder();
            foreach (int value in result)
            {
                char plainChar = letterIndexMap.First(x => x.Value == value).Key;
                plainText.Append(plainChar);
            }
            Console.WriteLine(plainText.ToString());

            return plainText.ToString();

        }

        public List<int> Analyse(List<int> plainText, List<int> cipherText)
        {
            bool flag = false;
            int x1 = 0, x2 = 0;
            List<int> key = new List<int>();

            for (int i = 0; i < 26; i++)
            {
                for (int j = 0; j < 26; j++)
                {
                    x1 = (i * plainText[0]) + (j * plainText[1]);
                    x2 = (i * plainText[2]) + (j * plainText[3]);
                    if ((x1 % 26 == cipherText[0]) && x2 % 26 == cipherText[2])
                    {
                        key.Add(i);
                        key.Add(j);
                        flag = true;
                        break;
                    }
                }
                if (flag == true)
                    break;
            }
            flag = false;

            for (int i = 0; i < 26; i++)
            {
                for (int j = 0; j < 26; j++)
                {
                    x1 = (i * plainText[0]) + (j * plainText[1]);
                    x2 = (i * plainText[2]) + (j * plainText[3]);
                    if ((x1 % 26 == cipherText[1]) && (x2 % 26 == cipherText[3]))
                    {
                        key.Add(i);
                        key.Add(j);
                        flag = true;
                        break;
                    }
                }
                if (flag == true)
                    break;
            }

            if (key.Count < 4)
            {
                throw new InvalidAnlysisException();
            }

            return key;

        }

        public string Analyse(string plainText, string cipherText)
        {
            List<int> plainTextIndices = ConvertToIndices(plainText);
            List<int> cipherTextIndices = ConvertToIndices(cipherText);

            List<int> key = Analyse(plainTextIndices, cipherTextIndices);

            StringBuilder Key = new StringBuilder();
            foreach (int value in key)
            {
                char keyChar = letterIndexMap.First(x => x.Value == value).Key;
                Key.Append(keyChar);
            }

            Console.WriteLine(Key.ToString());

            return Key.ToString();
        }

        public List<int> Analyse3By3Key(List<int> plain3, List<int> cipher3)
        {
            bool flag = false;
            int x1 = 0, x2 = 0, x3 = 0;
            List<int> key = new List<int>();

            for (int i = 0; i < 26; i++)
            {
                for (int j = 0; j < 26; j++)
                {
                    for (int k = 0; k < 26; k++)
                    {
                        x1 = (i * plain3[0]) + (j * plain3[1]) + (k * plain3[2]);
                        x2 = (i * plain3[3]) + (j * plain3[4]) + (k * plain3[5]);
                        x3 = (i * plain3[6]) + (j * plain3[7]) + (k * plain3[8]);

                        if ((x1 % 26 == cipher3[0]) && (x2 % 26 == cipher3[3]) && (x3 % 26 == cipher3[6]))
                        {
                            key.Add(i);
                            key.Add(j);
                            key.Add(k);
                            flag = true;
                            break;
                        }
                    }
                    if (flag == true)
                        break;
                }
                if (flag == true)
                    break;
            }
            flag = false;

            for (int i = 0; i < 26; i++)
            {
                for (int j = 0; j < 26; j++)
                {
                    for (int k = 0; k < 26; k++)
                    {
                        x1 = (i * plain3[0]) + (j * plain3[1]) + (k * plain3[2]);
                        x2 = (i * plain3[3]) + (j * plain3[4]) + (k * plain3[5]);
                        x3 = (i * plain3[6]) + (j * plain3[7]) + (k * plain3[8]);

                        if ((x1 % 26 == cipher3[1]) && (x2 % 26 == cipher3[4]) && (x3 % 26 == cipher3[7]))
                        {
                            key.Add(i);
                            key.Add(j);
                            key.Add(k);
                            flag = true;
                            break;
                        }
                    }
                    if (flag == true)
                        break;
                }
                if (flag == true)
                    break;
            }
            flag = false;

            for (int i = 0; i < 26; i++)
            {
                for (int j = 0; j < 26; j++)
                {
                    for (int k = 0; k < 26; k++)
                    {
                        x1 = (i * plain3[0]) + (j * plain3[1]) + (k * plain3[2]);
                        x2 = (i * plain3[3]) + (j * plain3[4]) + (k * plain3[5]);
                        x3 = (i * plain3[6]) + (j * plain3[7]) + (k * plain3[8]);

                        if ((x1 % 26 == cipher3[2]) && (x2 % 26 == cipher3[5]) && (x3 % 26 == cipher3[8]))
                        {
                            key.Add(i);
                            key.Add(j);
                            key.Add(k);
                            flag = true;
                            break;
                        }
                    }
                    if (flag == true)
                        break;
                }
                if (flag == true)
                    break;
            }

            if (key.Count < 9)
                throw new InvalidAnlysisException();

            for (int i = 0; i < key.Count; i++)
            {
                Console.WriteLine(key[i]);
            }

            return key;
        }

        public string Analyse3By3Key(string plain3, string cipher3)
        {
            List<int> plainTextIndices = ConvertToIndices(plain3);
            List<int> cipherTextIndices = ConvertToIndices(cipher3);

            List<int> key = Analyse3By3Key(plainTextIndices, cipherTextIndices);

            StringBuilder Key = new StringBuilder();
            foreach (int value in key)
            {
                char keyChar = letterIndexMap.First(x => x.Value == value).Key;
                Key.Append(keyChar);
            }

            string cipher = Encrypt(plain3, Key.ToString());

            cipher = cipher.ToUpper();

            Console.WriteLine(cipher);
            Console.WriteLine(cipher3);
            if (cipher.Equals(cipher3))
            {
                return Key.ToString();
            }
            else
            {
                throw new InvalidAnlysisException();
            }
        }
    }
}