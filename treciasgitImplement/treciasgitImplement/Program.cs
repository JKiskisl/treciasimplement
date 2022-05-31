using System;
using System.Numerics;
using System.Text;

namespace treciasgitImplement
{
    class MainClass
    {

        static void Main(string[] args)
        {
            int[] EncryptedNumbers;


            Console.WriteLine("Iveskite p: ");
            int p = Convert.ToInt32(Console.ReadLine());
            Console.WriteLine("Iveskite q: ");
            int q = Convert.ToInt32(Console.ReadLine());
            Console.WriteLine("Enter msg: ");
            String msg = Console.ReadLine();
            Console.WriteLine("----------");

            var encrypted = RSACiph.Encrypt(msg, p, q);
            char[] CipherText = new char[encrypted.Length];
            var plainBytes = Encoding.ASCII.GetBytes(msg);
            string plainNumbers = "";
            string cipherNumbers = "";
            EncryptedNumbers = new int[encrypted.Length];
            for (int i = 0; i < encrypted.Length; i++)
            {
                plainNumbers += int.Parse(plainBytes[i].ToString()) + " ";
                cipherNumbers += encrypted[i] + " ";
                CipherText[i] = (char)encrypted[i];
                EncryptedNumbers[i] = encrypted[i];
            }
            Console.WriteLine("Txt num value: " + plainNumbers);
            Console.WriteLine("Encrypted text num: " + cipherNumbers);
            string temp = "";
            foreach (char ch in CipherText)
            {
                temp += ch.ToString();
            }
            Console.WriteLine("Encrypted text: " + temp);

            Console.WriteLine("--------");


            string cipherNumbers1 = "";
            string plainNumbers1 = "";

            BigInteger[] keyPub1 = new BigInteger[2];
            BigInteger[] keyPriv1 = new BigInteger[2];
            keyPub1 = RSACiph.GetPublicKey();
            keyPriv1 = RSACiph.GetPrivateKey();

            string[] numberArray = cipherNumbers.Split(' ');
            var intArray = new int[numberArray.Length - 1];
            for (int i = 0; i < numberArray.Length - 1; i++)
            {
                intArray[i] = int.Parse(numberArray[i]);
            }
            var decrypted = RSACiph.Decrypt(intArray, keyPub1);
            var cipherBytes = Encoding.ASCII.GetBytes(msg);
            char[] plainText = new char[decrypted.Length];
            for (int i = 0; i < decrypted.Length; i++)
            {
                cipherNumbers1 += int.Parse(cipherBytes[i].ToString());
                plainNumbers1 += decrypted[i] + " ";
                plainText[i] = (char)decrypted[i];
            }
            Console.WriteLine("ciph msg value: " + cipherNumbers);
            Console.WriteLine("decrypted msg value: " + plainNumbers1);
            string temp1 = "";
            foreach (char ch in plainText)
            {
                temp1 += ch.ToString();
            }
            Console.WriteLine("Decrypted text: " + temp1);
            Console.WriteLine("------");

            Console.WriteLine("p: " + p);
            Console.WriteLine("q: " + q);
            Console.WriteLine("n: " + RSACiph.getN(p, q));
            Console.WriteLine("Fi(N): " + RSACiph.getFi(p, q));

            BigInteger[] keyPub = new BigInteger[2];
            BigInteger[] keyPriv = new BigInteger[2];
            keyPub = RSACiph.GetPublicKey();
            keyPriv = RSACiph.GetPrivateKey();

            Console.WriteLine("Public key: ( " + keyPub[0] + "; " + keyPub[1] + " )");
            Console.WriteLine("Private key:( " + keyPriv[0] + "; " + keyPriv[1] + " )");
        }
    }
}
