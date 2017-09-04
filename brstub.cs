using System;
using System.Security.Cryptography;
using System.IO;
using System.Text;

/// <summary>
/// Summary description for Class1
/// </summary>
public class brstub
{

    public byte[] Decrypted { get => decrypted; }
    private byte[] decrypted = null;
   

    public byte[] Key { get => key; set => key = value; }
    public byte[] Iv { get => iv; set => iv = value; }
    public byte[] Enc_exe { get => enc_exe; set => enc_exe = value; }

    private byte[] key;
    private byte[] iv;
    private byte[] enc_exe;



    //PRIVATE METHODS

    private static string GetMd5Hash(MD5 md5Hash, string input)
    {

        // Convert the input string to a byte array and compute the hash.
        byte[] data = md5Hash.ComputeHash(Encoding.UTF8.GetBytes(input));

        // Create a new Stringbuilder to collect the bytes
        // and create a string.
        StringBuilder sBuilder = new StringBuilder();

        // Loop through each byte of the hashed data 
        // and format each one as a hexadecimal string.
        for (int i = 0; i < data.Length; i++)
        {
            sBuilder.Append(data[i].ToString("x2"));
        }

        // Return the hexadecimal string.
        return sBuilder.ToString();
    }

    //PUBLIC METHODS


    /// <summary>
    /// Decrypt exe file .
    /// </summary>
    /// <returns>Byte array of decrypted file.</returns>
    public byte[] decrypt()
    {

        
        using (Aes aesdcr = Aes.Create())
        {
            aesdcr.BlockSize = 128;
            aesdcr.KeySize = 256;
            aesdcr.Mode = CipherMode.CBC;
    

            aesdcr.Key = key;
            aesdcr.IV = iv;

            ICryptoTransform decryptor = aesdcr.CreateDecryptor(aesdcr.Key, aesdcr.IV);

            using (var msDecrypt = new MemoryStream(enc_exe))
            {
                using (var csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                {
                    using (var srDecrypt = new StreamReader(csDecrypt))
                    {

                        // Read the decrypted bytes from the decrypting stream
                        // and place them in a string.
                        decrypted = srDecrypt.ReadToEnd();
                    }
                }
            }
        }

        return decrypted;
    }

    
    /// <summary>
    /// Check's decrypted file is correct.
    /// </summary>
    /// <param name="hashMD5">This is hash require to compare with decrypted file hash.</param>
    /// <returns>Return true if hashes are  same, false if hashes are different.</returns>
    public bool checkMD5(string hashMD5)
    {
        using ( MD5 md5Hash = MD5.Create())
        {
            // Hash the input.
            string hashOfInput = GetMd5Hash(md5Hash,decrypted);

            // Create a StringComparer an compare the hashes.
            StringComparer comparer = StringComparer.OrdinalIgnoreCase;

            if (0 == comparer.Compare(hashOfInput, hash))
            {
                return true;
            }
            else
            {
                return false;
            }
        }
    }
    
    /// <summary>
    /// Save decrypted array to file
    /// </summary>
    /// <param name="path">Path to save file</param>
    /// <returns>Return true if file's exist ,false if isn't exist.</returns>
    public bool saveFile(string path)
    {
        File.WriteAllBytes(path, decrypted);

        if (File.Exists(path)) return true;
        else return false;
    }
    
}
