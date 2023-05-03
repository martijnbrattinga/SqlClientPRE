// See https://aka.ms/new-console-template for more information
using Azure.Core;
using Microsoft.Data.SqlClient;
using Microsoft.SqlServer.Server;
using System.Collections;
using System.Configuration;
using System.Security.Cryptography;
using System.Text;

// Hardcoded proxy RSA keys for prototype purposes
// Note: very insecure
string privatekey = @"
        -----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQDKTBNkZWrC2cjw
/ sk7L0oW4G7nUIWJEz / 08DsZB + rk6EeQ2uGyNl6aOlIwrk7ZrCwlE2X1g3piS21v
3vTF8r9hdeyGIMHI7rWFyTeLLERU2ziC9WDVM69TiDDAFLIqVDFVB73mHOgNqBXX
sY6N + zq6mDv6lFLJO5hFRUskImkFx / VkowFqZNzX7quilGZaln1Jfxe2p6PIewmH
2RQHzMYb / UBlSs5rPO8IHpYvMk0wm1MvJL9Y + amz32frXGdas7beMbLdyXjWVUy3
iPIvjAfDczNxL1 / ZpD2OAq6nOvctuozyhbxerU8gx79xLA6gzXfTf8 / ey / s3ivQm
++53lRWRAgMBAAECggEASXSoUfs1cf1Mpp2Nik0YlQf3nUyywFxaC + GzQ9qJI4do
fSPNcj2lylDFCWIxxX5sJSZPDoAoT0reORH3RW1oqsX8FZQNaZ2sEiFHZuSzBzD2
6y6Yc7IpxqYcNZMOQqqBo0OFY + o5JMRU8hZKEioYYCrpFIsJKILYPsbzivJnui4E
4fK4OWBgr3hST4eHCH0e8Dp2tjK + 84tZGQLGigCQfYAmAG7BPCMayLlCv2DDug9C
aZJGh8OdLVrL11zEXFXzLUYWmkaSUwhEDMrLNqjz0W9OBi58l3FQ0MKM6jpvfo1z
wel0rj9 / 0JxdwwZ66c9 + QkjGB7ZGP4fyr6yejayGNQKBgQDvwh5Q9l9qPBJA + 3u2
f167dus0UZz / LIr3hAee2UegBlAVjdWLDbNBV3pNPdwQJ1Cheyh9mujC43JAfMQh
USMBFSze / YjGf6SXytMUzKxRQhqzM6oCT7rI0yjQNzKrYfddy6Mopy4W / gm8IW1s
qUdXsVrnBbwVtHn0W2fbeyjfVwKBgQDYAE7QJOysES8XcZ8x1IZelxVg + 7VazDcF
Xu0ZWJIYfz7HEaCZO / Lg4zaHvTMikwhxg5GKLF + dtJi7L858AecI6EGZVvNq / MK5
lQQCI + hTHHADIl + 3TSdXjebQWPQV3jDdriOJQLV9sYxXP9IazfZ0zG1DHvZLMgmg
u95zPg3pVwKBgFQP2ZVFbJrQyQ2jnvKToeFUho7ndoY5VdgGoK1fPS + sRvPnsNF6
Ujk8tJLUd43qWujjR4UShT2fhXV6yUFtMzqz8 / GTLxt5sXnPEUcfo + MxrC7clGUP
E0xKTOsED23rgVGPjns4cn55P2yIw9bvWyYx9s89QX7SslesnLNlcSUtAoGAHQ2V
jDubNd2t1tpqjjpGxIxPzNauYwMa13cYLxORuwfKet4tGs9McOE + 4W0aZqkeNp56
wfoL9ltnO65HeLiMyc7rm + NtJFPRIUMg4eTQh / VIP7Os6ivPgeBNTnLYieRz8C1P
DFQO1VQ / SzEDYqWXY8hnXeLZP + 4AC4WZeyi6mEsCgYB1ag + 7Rz9aDZ8XfU + AAU5t
inmC8Ihn54UZ / FrigVWIz8IzsYKSvctdNWf + 9Pk + vWSote9df8OjRk4C0jgoybiW
KtBOr0qL2I7rt0QPaSBCpvknFmSMKrwVekY2bcF00T / EmArD6N4TLjLP9bV3x / xn
dGhvHz35g4CXp40B9KUTJw ==
-----END PRIVATE KEY-----
";

string publickey = @"
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAykwTZGVqwtnI8P7JOy9K
FuBu51CFiRM/9PA7GQfq5OhHkNrhsjZemjpSMK5O2awsJRNl9YN6Ykttb970xfK/
YXXshiDByO61hck3iyxEVNs4gvVg1TOvU4gwwBSyKlQxVQe95hzoDagV17GOjfs6
upg7+pRSyTuYRUVLJCJpBcf1ZKMBamTc1+6ropRmWpZ9SX8XtqejyHsJh9kUB8zG
G/1AZUrOazzvCB6WLzJNMJtTLyS/WPmps99n61xnWrO23jGy3cl41lVMt4jyL4wH
w3MzcS9f2aQ9jgKupzr3LbqM8oW8Xq1PIMe/cSwOoM1303/P3sv7N4r0Jvvud5UV
kQIDAQAB
-----END PUBLIC KEY-----
";

//**** Settings ****//
int test = 1; // 0 = ExecuteScalar (INSERT), 1=ExecuteReader (SELECT WHERE)
bool AlwaysEncrypted = true;
string PRE = ""; // Bidirectional, Forward, Backward, BidirectionalTEE, ForwardTEE, BackwardTEE
Console.WriteLine("Running the SQL test program with AE=" + AlwaysEncrypted + " and PRE=" + PRE);


// Create 'proxy' RSA object from hardcoded key
RSA rsa_proxy = RSA.Create();
rsa_proxy.ImportFromPem(privatekey);
byte[] publickeyBytesProxy = Encoding.UTF8.GetBytes(rsa_proxy.ExportSubjectPublicKeyInfoPem());

// Creating 'client' AES object
Aes aes_client = Aes.Create();
aes_client.Mode = CipherMode.CBC;

// Creating 'client' RSA object
RSA rsa_client = RSA.Create();
byte[] publickeyBytesClient = Encoding.UTF8.GetBytes(rsa_client.ExportSubjectPublicKeyInfoPem());

// Setting the Connection string for the normal, Always Encrypted, and Always Encrypted using TEE configurations.
string connectionString;
if (AlwaysEncrypted)
{
    connectionString = "Data Source=.;Initial Catalog=rdwae;Column Encryption Setting=Enabled;Attestation Protocol=None; Integrated Security=true; Encrypt=False; Column Encryption PRE Setting=" + PRE;
}
else
{
    connectionString = "Data Source=.;Initial Catalog=rdwae;Encrypt=False;Integrated Security=True;Encrypt=False";
}






if (test == 0) // Execute Scalar
{

    //**** BEGIN CLIENT CODE ****//

    // The client encrypts the value before sending the request to the proxy
    byte[] val_encrypted_bsn = aes_client.EncryptCbc(new byte[] { 123, 0, 0, 0 }, aes_client.IV); // Encrypted the query parameter value
    byte[] val_encrypted_lastname = aes_client.EncryptCbc(Encoding.ASCII.GetBytes("de Klein"), aes_client.IV); // Encrypted the query parameter value
    byte[] val_encrypted_postalcode = aes_client.EncryptCbc(Encoding.ASCII.GetBytes("3781AD"), aes_client.IV); // Encrypted the query parameter value

    // Encrypt key and IV toward public key of proxy
    byte[] encryptedSymmetricKey = rsa_proxy.Encrypt(aes_client.Key, RSAEncryptionPadding.OaepSHA256);
    byte[] encryptedSymmetricIV = rsa_proxy.Encrypt(aes_client.IV, RSAEncryptionPadding.OaepSHA256);
    // The encrypted parameter gets send to the proxy

    //**** END CLIENT CODE, BEGIN PROXY CODE ****//

    using (SqlConnection connection = new SqlConnection(connectionString))
    {
        SqlCommand cmd = connection.CreateCommand();
        cmd.CommandText = @"INSERT dbo.Users ([BSN], [firstname], [lastname], [birth_date], [birth_place], [postal_code], [house_nr]) VALUES (@BSN, @FirstName, @LastName, @BirthDate, @Birthplace, @PostalCode, @HouseNr);" +
        "SELECT CAST(scope_identity() AS int)"; // INSERT query targeteting encrypted columns BSN, lastname, postal_code
        cmd.PREPublicKey = publickeyBytesClient; // Setting the public key of the client, such that the data can be encrypted towards this key on result. (Actually only used for key encapsulation, where the data is encrypted 
        cmd.PREEncryptedSymmetricKey = encryptedSymmetricKey; // Received encrypted session key from client; Can be used to decrypt incoming data.
        cmd.PREEncryptedSymmetricIV = encryptedSymmetricIV; // Received encrypted session IV from client; Can be used to decrypt incoming data.

        SqlParameter pbsn = new SqlParameter("@BSN", System.Data.SqlDbType.Int);
        pbsn.Value = val_encrypted_bsn;
        cmd.Parameters.Add(pbsn); // Encrypted BSN column
        cmd.Parameters.Add(new SqlParameter("@FirstName", "M"));
        SqlParameter plastname = new SqlParameter(parameterName: "@LastName", System.Data.SqlDbType.VarChar);
        plastname.Value = val_encrypted_lastname;
        cmd.Parameters.Add(plastname); // Encrypted Lastname column
        cmd.Parameters.Add(new SqlParameter("@BirthDate", "20-05-1993"));
        cmd.Parameters.Add(new SqlParameter("@Birthplace", "Grootbroek"));
        SqlParameter ppostalcode = new SqlParameter("@PostalCode", System.Data.SqlDbType.VarChar);
        ppostalcode.Value = val_encrypted_postalcode;
        cmd.Parameters.Add(ppostalcode); // Encrypted Postal code column
        cmd.Parameters.Add(new SqlParameter("@HouseNr", "1191"));



        connection.Open();
        try
        {
            var result = cmd.ExecuteScalar();
            if (result != null)
            { // Nothing special, as the user ID column is not encrypted
                Int32 user_id = (Int32)result;
                Console.WriteLine("Got new user ID: " + user_id);
                // result
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine("Exception in adding user: " + ex.Message);
        }
    }
}
else if (test == 1){ // ExecuteReader
    //**** BEGIN CLIENT CODE ****//

    // The client encrypts the value before sending the request to the proxy
    byte[] val = new byte[] { 3, 0, 0, 0 }; // Integer encoding of 3
    val = aes_client.EncryptCbc(val, aes_client.IV); // Encrypted the query parameter value
    // Encrypt key and IV toward public key of proxy
    byte[] encryptedSymmetricKey = rsa_proxy.Encrypt(aes_client.Key, RSAEncryptionPadding.OaepSHA256); 
    byte[] encryptedSymmetricIV = rsa_proxy.Encrypt(aes_client.IV, RSAEncryptionPadding.OaepSHA256);

    // The encrypted parameter gets send to the proxy
    //**** END CLIENT CODE, BEGIN PROXY CODE ****//


    using (SqlConnection connection = new SqlConnection(connectionString))
    {
        SqlCommand cmd = connection.CreateCommand();
        cmd.CommandText = @"SELECT * FROM users WHERE BSN=@BSN"; // SELECT query targetting the encrypted column BSN
        if (AlwaysEncrypted && (PRE == "Forward" || PRE=="Backward" || PRE == "Bidirectional" || PRE == "ForwardTEE" || PRE=="BackwardTEE" || PRE == "BidirectionalTEE"))
        {

            cmd.PREPublicKey = publickeyBytesClient; // Setting the public key of the client, such that the data can be encrypted towards this key on result. (Actually only used for key encapsulation, where the data is encrypted using AES; IV and Key using RSA)
            cmd.PREEncryptedSymmetricKey = encryptedSymmetricKey; // Received encrypted session key from client; Can be used to decrypt incoming data.
            cmd.PREEncryptedSymmetricIV = encryptedSymmetricIV; // Received encrypted session IV from client; Can be used to decrypt incoming data.
        }
        //SqlParameter p = new SqlParameter("@Lastname", System.Data.SqlDbType.VarChar);
        //p.Value = new byte[] { 67, 97, 109, 112 };
        //p.Value = "Camp";

        
        // If PRE is used set the encrypted value (in bytes), otherwise just use normal integer value
        SqlParameter p = new SqlParameter("@BSN", System.Data.SqlDbType.Int);
        if (AlwaysEncrypted && PRE != "" && PRE != "Disabled")
        {
            p.Value = val;
        }
        else 
        {
            p.Value = 3;
        }
        cmd.Parameters.Add(p);


        // Open connection and execute query
        
        connection.Open();
        using (SqlDataReader reader = cmd.ExecuteReader())
        {
            while (reader.Read())
            {
                if (AlwaysEncrypted)
                {
                    if (PRE == "Backward" || PRE == "Bidirectional" || PRE == "BackwardTEE" || PRE == "BidirectionalTEE")
                    { // Always encrypted with proxy re-encryption is enabled, thus our response is encrypted bytes

                        // The proxy only has access to the encrypted bytes, which only the client can decrypt
                        byte[] bsn = (byte[])reader.GetValue(reader.GetOrdinal("bsn"));
                        byte[] lastname = (byte[])reader.GetValue(reader.GetOrdinal("lastname"));
                        Console.WriteLine("bsn bytes: [{0}]", string.Join(", ", bsn));
                        Console.WriteLine("lastname bytes: [{0}]", string.Join(", ", lastname));
                        Console.WriteLine();

                        //**** END PROXY CODE, BEGIN CLIENT CODE ****//

                        // The result would be sent back to the client.
                        // For demonstration purposes, we execute the code that normally would be run on the client. Only the client has access to 
                        byte[] decryptedBSN;
                        byte[] decryptedLastname;


                        // We re-use the session key and IV from the client request; Note: we should not re-use the IV;
                        // especially since there is no guarantee the IV is uniquely created at the client each request
                        //aes_client.Key =  rsa_client.Decrypt(key?, RSAEncryptionPadding.OaepSHA256);
                        //aes_client.IV = rsa_client.Decrypt(iv?, RSAEncryptionPadding.OaepSHA256);

                        decryptedBSN = aes_client.DecryptCbc(bsn, aes_client.IV); // Decrypt the bsn
                        decryptedLastname = aes_client.DecryptCbc(lastname, aes_client.IV); // Decrypt the lastname (also an encrypted column)

                        Console.WriteLine("decrypted bsn bytes: [{0}]", string.Join(", ", decryptedBSN));
                        Console.WriteLine("decrypted lastname bytes: [{0}]", string.Join(", ", decryptedLastname));
                        Console.WriteLine("decrypted lastname decoded: " + Encoding.UTF8.GetString(decryptedLastname));
                        Console.WriteLine();

                        //**** END PROXY CODE, END ****//

                    }
                    else
                    { // Always encrypted is enabled, but PRE is not; Transparent to the proxy, thus we can obtain the string directly from the resultset
                        string bsn = reader.GetString(reader.GetOrdinal("lastname"));
                        Console.WriteLine("Transparent AE lastname: " + bsn);
                    }

                }
                else
                { // Always encrypted is not enabled here, but it is on the column in the database. Therefore we obtain the raw bytes from the database, encrypted under the database CEK
                    byte[] bsn = (byte[])reader.GetValue(reader.GetOrdinal("lastname"));
                    string bsn_string = Convert.ToBase64String(bsn);
                    Console.WriteLine("Raw bytes lastname: " + bsn_string);
                }

            }
            reader.Close();
        }
    }
}





// Small function to create RSA keys in PEM format
void dummyRSAGenerator()
{
    Console.WriteLine("Running RSA generate key");


    string testmessage = "cs3oxbshoo4hO211sTD0WwS+32qkPICCEVhbeSodxndMHldCh7f+jFuiFHnSH4F443Au6vpgmdbgBuoY73HK+4qrvQCfOhEJNLraxL5/KJT9jsvMlciobT1HfmKIoSgXkaJJRjkLjMMWmDlwqwR9eBtI6UGywe2+IV+ekRukemzNqNO9lLZcEdiOWX88WAF4PaPlqaXu5CPhBKlYLoUTwE7reL8RWO/+cvYuqPYybVAB1dIgQ4pc97Bnd650mSxUp8hMy7BftEMTs+EvvLUw2Ob3wJYwyWKaBQpHrJeznZHz80XWzNLiq2a3n2L30iIwEc23P1mHcZNMdVYZkXaUtg==";

    Console.WriteLine("Dummy RSA");
    RSA rsa = RSA.Create();
    //Console.WriteLine("RSA Private key:");
    //Console.WriteLine(rsa.ExportPkcs8PrivateKeyPem());
    //Console.WriteLine();

    rsa.ImportFromPem(privatekey);
    Console.WriteLine("RSA Public key:");
    Console.WriteLine(rsa.ExportSubjectPublicKeyInfoPem());
    Console.WriteLine();
    byte[] c = Convert.FromBase64String(testmessage);
    Console.WriteLine("Decrypting message");
    byte[] m = rsa.Decrypt(c, RSAEncryptionPadding.OaepSHA256);
    string mtext = Encoding.Default.GetString(m);
    Console.WriteLine("Result: " + mtext);

}
