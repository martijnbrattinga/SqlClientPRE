using System.Collections.Generic;
using System.Data;
using System.Security.Cryptography;
using System.Text;
using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Columns;
using BenchmarkDotNet.Configs;
using BenchmarkDotNet.Reports;
using Microsoft.Data.SqlClient;
using Microsoft.Extensions.Configuration;

namespace TesterSqlClient
{
    [MarkdownExporter, AsciiDocExporter, HtmlExporter, CsvExporter, RPlotExporter]
    [Config(typeof(Config))]
    //[SimpleJob(RunStrategy.ColdStart, launchCount: 4, warmupCount: 3, iteration: 20, id: "MyJob")]
    public class Tests
    {

        bool debug = false;
        string connectionString;
        string connectionStringAE;

        Aes aes_client;
        RSA rsa_client;
        RSA rsa_proxy;

        Random random;

        public Tests() : this(false)
        {

        }

        public Tests(bool debug)
        {
            var config = new ConfigurationBuilder().AddUserSecrets<Program>().Build();
            this.debug = debug;


            this.connectionStringAE = "Data Source=.;Initial Catalog=rdwae;Column Encryption Setting=Enabled;Attestation Protocol=None; Integrated Security=true; Encrypt=False;";
            this.connectionString = "Data Source=.;Initial Catalog=rdwae;Encrypt=False;Integrated Security=True;Encrypt=False";


            //  ENABLED FOR STUDENT AZURE DB
            //this.connectionString = config.GetSection("Database:Azure").GetValue("ConnectionString", "");
            //this.connectionStringAE = config.GetSection("Database:Azure").GetValue("ConnectionStringAE", "");

            //  ENABLED FOR STUDENT AZURE DB no SGX but VBS
            //this.connectionString = config.GetSection("Database:AzureVBS").GetValue("ConnectionString", "");
            //this.connectionStringAE = config.GetSection("Database:AzureVBS").GetValue("ConnectionStringAE", "");

            //SetAzureKeyvaultProvider();




            this.aes_client = Aes.Create();
            this.aes_client.Mode = CipherMode.CBC;
            this.rsa_client = RSA.Create();
            this.rsa_proxy = RSA.Create();
            this.rsa_proxy.ImportFromPem(privatekey); // Hardcoded private key at bottom of this class

            this.random = new Random();

            Console.WriteLine("constructor of Tests called");


        }


        private void SetAzureKeyvaultProvider()
        {
            // Does not seem to work with our custom version of the SqlConnector yet
            /*
            string s_akvUrl = "https://{KeyVaultName}.vault.azure.net/keys/{Key}/{KeyIdentifier}";
            InteractiveBrowserCredential interactiveBrowserCredential = new InteractiveBrowserCredential();

            // Initialize AKV provider
            SqlColumnEncryptionAzureKeyVaultProvider akvProvider = new SqlColumnEncryptionAzureKeyVaultProvider(interactiveBrowserCredential);

            // Register AKV provider
            SqlConnection.RegisterColumnEncryptionKeyStoreProviders(customProviders: new Dictionary<string, SqlColumnEncryptionKeyStoreProvider>(capacity: 1, comparer: StringComparer.OrdinalIgnoreCase)
                {
                    { SqlColumnEncryptionAzureKeyVaultProvider.ProviderName, akvProvider}
                });
            */
        }


        /*
         * Run the unbounded retrieval queries with these limits (max. rows returned)
         */
        public IEnumerable<int> TryLimits()
        {
            yield return 1;
            yield return 10;
            yield return 100;
            yield return 1000;
            //yield return 10000;
        }

        /*
         * Run the insertion queries with these amount of rows to insert
         */
        public IEnumerable<int> TryInsertAmounts()
        {
            yield return 1;
            yield return 10;
            yield return 100;
            yield return 1000;
        }
        /*
         * Determines the amount of insertion data to be generated, 
         * thus should correspond with the max of TryInsertAmounts()
         */
        const int max_insert_rows = 1000;


        /*
         * The database size of the current iteration.
         * Not that running all tests consequtively can take a very, very long time
         */
        [Params(100000)]
        //[Params(1000,10000,100000,1000000,10000000)]
        public int DB_SIZE { get; set; }




        /*
         * Set-up for each test.
         * Clears the database and re-initializes the database. For the large tests this takes very long, thus might be disabled.
         * The idea is that inserting 1000 rows for a database of size 1000 messes up the measurements, while inserting 1000 rows for database size 10M is less impactfull.
         * Would be more efficient to just determine the difference between DB_size and GetUserRowsCount() and modifiy the database accordingly.
         */
        [GlobalSetup]
        public void GlobalSetup()
        {
            Console.WriteLine("Global setup with DB_SIZE: " + DB_SIZE + " and current database rows: " + GetUserRowsCount());

            ClearDatabase();
            InitializeDatabase(DB_SIZE);
        }


        /*
         *  Manually run all tests, e.g. to test if functionality not broken
         */
        public bool TestAll()
        {
            bool result = true;
            int limit = 10;
            int insert_amount = 5;

            // Plaintext version
            TestNormal_GetPlainColumns(limit);
            TestNormal_GetEncryptedColumns(limit);
            TestNormal_GetWherePlain();
            TestNormal_GetJoinPlain(limit);

            // Always Encrypted version
            TestAE_GetPlainColumns(limit);
            TestAE_GetEncryptedColumns(limit);
            TestAE_GetWherePlain(3);
            TestAE_GetWhereEncrypted(3);
            TestAE_GetJoinPlain(limit);
            Setup_TestAE_InsertRow();
            TestAE_InsertRow(insert_amount);
            Cleanup_TestAE_InsertRow();


            // Setup client data
            byte[] encryptedSymmetricKey = rsa_proxy.Encrypt(aes_client.Key, RSAEncryptionPadding.OaepSHA256);
            byte[] encryptedSymmetricIV = rsa_proxy.Encrypt(aes_client.IV, RSAEncryptionPadding.OaepSHA256);
            byte[] publickeyBytesClient = Encoding.UTF8.GetBytes(rsa_client.ExportSubjectPublicKeyInfoPem());
            byte[] bsn_3_encrypted = aes_client.EncryptCbc(new byte[] { 3, 0, 0, 0 }, aes_client.IV);

            // PRE C# version
            string PRESetting = "Column Encryption PRE Setting=" + "Bidirectional";
            TestPRE_GetPlainColumns(limit, PRESetting);
            TestPRE_GetEncryptedColumns(limit, PRESetting, publickeyBytesClient, encryptedSymmetricKey, encryptedSymmetricIV);
            TestPRE_GetWherePlain(PRESetting, publickeyBytesClient, encryptedSymmetricKey, encryptedSymmetricIV, 3);
            TestPRE_GetWhereEncrypted(PRESetting, publickeyBytesClient, encryptedSymmetricKey, encryptedSymmetricIV, bsn_3_encrypted);
            TestPRE_GetJoinPlain(limit, PRESetting, publickeyBytesClient, encryptedSymmetricKey, encryptedSymmetricIV);
            Setup_TestPRE_InsertRow();
            TestPRE_InsertRow(insert_amount, PRESetting, publickeyBytesClient, encryptedSymmetricKey, encryptedSymmetricIV);
            Cleanup_TestPRE_InsertRow();

            // PRE Trusted Execution Environment version
            PRESetting = "Column Encryption PRE Setting=" + "BidirectionalTEE";
            TestPRE_GetPlainColumns(limit, PRESetting);
            TestPRE_GetEncryptedColumns(limit, PRESetting, publickeyBytesClient, encryptedSymmetricKey, encryptedSymmetricIV);
            TestPRE_GetWherePlain(PRESetting, publickeyBytesClient, encryptedSymmetricKey, encryptedSymmetricIV, 3);
            TestPRE_GetWhereEncrypted(PRESetting, publickeyBytesClient, encryptedSymmetricKey, encryptedSymmetricIV, bsn_3_encrypted);
            TestPRE_GetJoinPlain(limit, PRESetting, publickeyBytesClient, encryptedSymmetricKey, encryptedSymmetricIV);
            Setup_TestPRE_InsertRow();
            TestPRE_InsertRow(insert_amount, PRESetting, publickeyBytesClient, encryptedSymmetricKey, encryptedSymmetricIV);
            Cleanup_TestPRE_InsertRow();


            return result; //dummy
        }


        /*
         * Single test for debugging
         */
        public bool TestSingle()
        {
            byte[] encryptedSymmetricKey = rsa_proxy.Encrypt(aes_client.Key, RSAEncryptionPadding.OaepSHA256);
            byte[] encryptedSymmetricIV = rsa_proxy.Encrypt(aes_client.IV, RSAEncryptionPadding.OaepSHA256);
            byte[] publickeyBytesClient = Encoding.UTF8.GetBytes(rsa_client.ExportSubjectPublicKeyInfoPem());
            string PRESetting = "Column Encryption PRE Setting=" + "BidirectionalTEE";

            //TestPRE_GetEncryptedColumns(100, PRESetting, publickeyBytesClient, encryptedSymmetricKey, encryptedSymmetricIV);


            
            for (int i = 0; i < 255; i++)
            {
                byte[] inp = new byte[] { (byte)i, 0, 0, 0, 0, 0, 0, 0}; // it works starting from 167,120,73,0 = 4815015
                //Console.WriteLine("Iteration " + i + "(thus " + inp[0] + "," + inp[1] + "," + inp[2] + "," + inp[3] + ")");
                byte[] bsn_3_encrypted = aes_client.EncryptCbc(inp, aes_client.IV); // 199, 30, 17, 0
                //TestAE_GetWhereEncrypted(3);
                TestPRE_GetWhereEncrypted(PRESetting, publickeyBytesClient, encryptedSymmetricKey, encryptedSymmetricIV, bsn_3_encrypted);

            }

            return true;
        }








        /**************** Non-AE tests ****************/
        /*
         * Tests involving the database with encrypted columns, but without Always Encrypted
         * enabled in the SqlConnection. Therefore, encrypted columns are returned as
         * (encrypted) bytes.
         * Not that targetting encrypted columns, besides in the select columns, is not
         * possible. Therefore not all tests can be run using non-AE.
         */


        [Benchmark]
        [ArgumentsSource(nameof(TryLimits))]
        public void TestNormal_GetPlainColumns(int limit)
        {
            TestPrint("Normal getting 3 plain columns");

            using (SqlConnection connection = new SqlConnection(connectionString))
            {
                using (SqlCommand cmd = connection.CreateCommand())
                {
                    cmd.CommandText = @"SELECT TOP(@Limit) id, firstname, birth_place FROM users";

                    SqlParameter p = new SqlParameter("@Limit", System.Data.SqlDbType.Int);
                    p.Value = limit;
                    cmd.Parameters.Add(p);

                    int received_i = 0;

                    connection.Open();
                    using (SqlDataReader reader = cmd.ExecuteReader())
                    {
                        while (reader.Read())
                        {
                            {
                                int id_string = reader.GetInt32(reader.GetOrdinal("id"));
                                string firstname_string = reader.GetString(reader.GetOrdinal("firstname"));
                                string birth_place_string = reader.GetString(reader.GetOrdinal("birth_place"));

                                TestPrint("Normal firstname: " + firstname_string);
                                received_i++;
                            }

                        }
                        reader.Close();
                    }
                    TestPrint("Done receiving data (" + received_i + "/" + limit + ")");
                }
            }

            TestPrint("");

        }

        [Benchmark]
        [ArgumentsSource(nameof(TryLimits))]
        public void TestNormal_GetEncryptedColumns(int limit)
        {
            TestPrint("Normal getting 3 encrypted columns");
            using (SqlConnection connection = new SqlConnection(connectionString))
            {
                using (SqlCommand cmd = connection.CreateCommand())
                {
                    cmd.CommandText = @"SELECT TOP(@Limit) bsn, lastname, postal_code FROM users";

                    SqlParameter p = new SqlParameter("@Limit", System.Data.SqlDbType.Int);
                    p.Value = limit;
                    cmd.Parameters.Add(p);

                    int received_i = 0;

                    connection.Open();
                    using (SqlDataReader reader = cmd.ExecuteReader())
                    {
                        while (reader.Read())
                        {
                            { // Always encrypted is not enabled here, but it is on the column in the database. Therefore we obtain the raw bytes from the database, encrypted under the database CEK
                                byte[] bsn = (byte[])reader.GetValue(reader.GetOrdinal("bsn"));
                                byte[] lastname = (byte[])reader.GetValue(reader.GetOrdinal("lastname"));
                                byte[] postal_code = (byte[])reader.GetValue(reader.GetOrdinal("postal_code"));

                                string lastname_string = Convert.ToBase64String(lastname);
                                TestPrint("Normal bsn (encoded): " + lastname_string);

                                received_i += 1;
                            }

                        }
                        reader.Close();
                    }
                    TestPrint("Done receiving data (" + received_i + "/" + limit + ")");
                }
            }

            TestPrint("");
        }

        [Benchmark]
        public void TestNormal_GetWherePlain()
        {
            TestPrint("Normal getting columns where plain");

            using (SqlConnection connection = new SqlConnection(connectionString))
            {
                using (SqlCommand cmd = connection.CreateCommand())
                {
                    cmd.CommandText = @"SELECT * FROM users WHERE id = @Id";

                    SqlParameter p2 = new SqlParameter("@Id", System.Data.SqlDbType.Int);
                    p2.Value = 4;
                    cmd.Parameters.Add(p2);

                    int received_i = 0;

                    connection.Open();
                    using (SqlDataReader reader = cmd.ExecuteReader())
                    {
                        while (reader.Read())
                        {
                            { // Always encrypted is not enabled here, but it is on the column in the database. Therefore we obtain the raw bytes from the database, encrypted under the database CEK
                                int id = reader.GetInt32(reader.GetOrdinal("id"));
                                byte[] bsn = (byte[])reader.GetValue(reader.GetOrdinal("bsn"));
                                string firstname = reader.GetString(reader.GetOrdinal("firstname"));
                                byte[] lastname = (byte[])reader.GetValue(reader.GetOrdinal("lastname"));
                                DateTime birth_date = reader.GetDateTime(reader.GetOrdinal("birth_date"));
                                string birth_place = reader.GetString(reader.GetOrdinal("birth_place"));
                                byte[] postal_code = (byte[])reader.GetValue(reader.GetOrdinal("postal_code"));
                                string house_nr = reader.GetString(reader.GetOrdinal("house_nr"));

                                string lastname_string = Convert.ToBase64String(lastname);
                                TestPrint("Normal lastname (encoded): " + lastname_string);

                                received_i++;
                            }

                        }
                        reader.Close();
                    }
                    TestPrint("Done receiving data (" + received_i + ")");
                }
            }

            TestPrint("");
        }

        [Benchmark]
        [ArgumentsSource(nameof(TryLimits))]
        public void TestNormal_GetJoinPlain(int limit)
        {
            TestPrint("Normal getting columns joined on plain");

            using (SqlConnection connection = new SqlConnection(connectionString))
            {
                using (SqlCommand cmd = connection.CreateCommand())
                {
                    cmd.CommandText = @"SELECT TOP(@Limit) * FROM users JOIN DriversLicenses ON Users.id=DriversLicenses.user_id;";

                    SqlParameter p = new SqlParameter("@Limit", System.Data.SqlDbType.Int);
                    p.Value = limit;
                    cmd.Parameters.Add(p);

                    int received_i = 0;

                    connection.Open();
                    using (SqlDataReader reader = cmd.ExecuteReader())
                    {
                        while (reader.Read())
                        {
                            { // Always encrypted is not enabled here, but it is on the column in the database. Therefore we obtain the raw bytes from the database, encrypted under the database CEK
                                int id = reader.GetInt32(reader.GetOrdinal("id"));
                                byte[] bsn = (byte[])reader.GetValue(reader.GetOrdinal("bsn"));
                                string firstname = reader.GetString(reader.GetOrdinal("firstname"));
                                byte[] lastname = (byte[])reader.GetValue(reader.GetOrdinal("lastname"));
                                DateTime birth_date = reader.GetDateTime(reader.GetOrdinal("birth_date"));
                                string birth_place = reader.GetString(reader.GetOrdinal("birth_place"));
                                byte[] postal_code = (byte[])reader.GetValue(reader.GetOrdinal("postal_code"));
                                string house_nr = reader.GetString(reader.GetOrdinal("house_nr"));

                                int drivers_license_id = reader.GetInt32(reader.GetOrdinal("drivers_license_id"));
                                DateTime assigned = reader.GetDateTime(reader.GetOrdinal("assigned"));
                                DateTime expired = reader.GetDateTime(reader.GetOrdinal("expired"));
                                int penalty_points = reader.GetInt32(reader.GetOrdinal("penalty_points"));


                                string lastname_string = Convert.ToBase64String(lastname);
                                TestPrint("Normal lastname (encoded): " + lastname_string);

                                received_i++;
                            }

                        }
                        reader.Close();
                    }
                    TestPrint("Done receiving data (" + received_i + "/" + limit + ")");
                }
            }

            TestPrint("");
        }




        /**************** AE tests ****************/

        [Benchmark]
        [ArgumentsSource(nameof(TryLimits))]
        public void TestAE_GetPlainColumns(int limit)
        {
            TestPrint("AE getting 3 plain columns");

            using (SqlConnection connection = new SqlConnection(connectionStringAE))
            {
                using (SqlCommand cmd = connection.CreateCommand())
                {
                    cmd.CommandText = @"SELECT TOP(@Limit) id, firstname, birth_place FROM users";

                    SqlParameter p = new SqlParameter("@Limit", System.Data.SqlDbType.Int);
                    p.Value = limit;
                    cmd.Parameters.Add(p);

                    int received_i = 0;

                    connection.Open();
                    using (SqlDataReader reader = cmd.ExecuteReader())
                    {
                        while (reader.Read())
                        {
                            {
                                int id = reader.GetInt32(reader.GetOrdinal("id"));
                                string firstname = reader.GetString(reader.GetOrdinal("firstname"));
                                string birth_place = reader.GetString(reader.GetOrdinal("birth_place"));
                                TestPrint("AE firstname: " + firstname);
                                received_i++;
                            }

                        }
                        reader.Close();
                    }
                    TestPrint("Done receiving data (" + received_i + "/" + limit + ")");
                }
            }

            TestPrint("");
        }

        [Benchmark]
        [ArgumentsSource(nameof(TryLimits))]
        public void TestAE_GetEncryptedColumns(int limit)
        {
            TestPrint("AE getting 3 encrypted columns");

            using (SqlConnection connection = new SqlConnection(connectionStringAE))
            {
                using (SqlCommand cmd = connection.CreateCommand())
                {
                    cmd.CommandText = @"SELECT TOP(@Limit) bsn, lastname, postal_code FROM users";

                    SqlParameter p = new SqlParameter("@Limit", System.Data.SqlDbType.Int);
                    p.Value = limit;
                    cmd.Parameters.Add(p);

                    int received_i = 0;

                    connection.Open();
                    using (SqlDataReader reader = cmd.ExecuteReader())
                    {
                        while (reader.Read())
                        {
                            {
                                int bsn = reader.GetInt32(reader.GetOrdinal("bsn"));
                                string lastname = reader.GetString(reader.GetOrdinal("lastname"));
                                string postal_code = reader.GetString(reader.GetOrdinal("postal_code"));

                                TestPrint("AE lastname: " + lastname);
                                received_i++;
                            }

                        }
                        reader.Close();
                    }
                    TestPrint("Done receiving data (" + received_i + "/" + limit + ")");
                }
            }

            TestPrint("");
        }

        [Benchmark]
        public void TestAE_GetWherePlain(int query_id = 3)
        {
            TestPrint("AE getting columns where plain");

            using (SqlConnection connection = new SqlConnection(connectionStringAE))
            {
                using (SqlCommand cmd = connection.CreateCommand())
                {
                    cmd.CommandText = @"SELECT * FROM users WHERE id = @Id";

                    SqlParameter p2 = new SqlParameter("@Id", System.Data.SqlDbType.Int);
                    p2.Value = query_id;
                    cmd.Parameters.Add(p2);

                    int received_i = 0;

                    connection.Open();
                    using (SqlDataReader reader = cmd.ExecuteReader())
                    {
                        while (reader.Read())
                        {
                            { // Always encrypted is not enabled here, but it is on the column in the database. Therefore we obtain the raw bytes from the database, encrypted under the database CEK
                                int id = reader.GetInt32(reader.GetOrdinal("id"));
                                int bsn = reader.GetInt32(reader.GetOrdinal("bsn"));
                                string firstname = reader.GetString(reader.GetOrdinal("firstname"));
                                string lastname = reader.GetString(reader.GetOrdinal("lastname"));
                                DateTime birth_date = reader.GetDateTime(reader.GetOrdinal("birth_date"));
                                string birth_place = reader.GetString(reader.GetOrdinal("birth_place"));
                                string postal_code = reader.GetString(reader.GetOrdinal("postal_code"));
                                string house_nr = reader.GetString(reader.GetOrdinal("house_nr"));

                                TestPrint("AE lastname: " + lastname);
                                received_i++;
                            }

                        }
                        reader.Close();
                    }
                    TestPrint("Done receiving data (" + received_i + ")");
                }
            }

            TestPrint("");
        }

        [Benchmark]
        public void TestAE_GetWhereEncrypted(int query_bsn = 3)
        {
            TestPrint("AE getting columns where encrypted");

            using (SqlConnection connection = new SqlConnection(connectionStringAE))
            {
                using (SqlCommand cmd = connection.CreateCommand())
                {
                    cmd.CommandText = @"SELECT * FROM users WHERE bsn = @BSN";
                    cmd.CommandTimeout = 120; // Required for when db has 10 million entries

                    SqlParameter p2 = new SqlParameter("@BSN", System.Data.SqlDbType.Int);
                    p2.Value = query_bsn;
                    cmd.Parameters.Add(p2);

                    int received_i = 0;

                    connection.Open();
                    using (SqlDataReader reader = cmd.ExecuteReader())
                    {
                        while (reader.Read())
                        {
                            { // Always encrypted is not enabled here, but it is on the column in the database. Therefore we obtain the raw bytes from the database, encrypted under the database CEK
                                int id = reader.GetInt32(reader.GetOrdinal("id"));
                                int bsn = reader.GetInt32(reader.GetOrdinal("bsn"));
                                string firstname = reader.GetString(reader.GetOrdinal("firstname"));
                                string lastname = reader.GetString(reader.GetOrdinal("lastname"));
                                DateTime birth_date = reader.GetDateTime(reader.GetOrdinal("birth_date"));
                                string birth_place = reader.GetString(reader.GetOrdinal("birth_place"));
                                string postal_code = reader.GetString(reader.GetOrdinal("postal_code"));
                                string house_nr = reader.GetString(reader.GetOrdinal("house_nr"));

                                TestPrint("AE lastname: " + lastname);
                                received_i++;
                            }

                        }
                        reader.Close();
                    }
                    TestPrint("Done receiving data (" + received_i + ")");
                }
            }

            TestPrint("");
        }

        [Benchmark]
        [ArgumentsSource(nameof(TryLimits))]
        public void TestAE_GetJoinPlain(int limit)
        {
            TestPrint("AE getting columns joined on plain");

            using (SqlConnection connection = new SqlConnection(connectionStringAE))
            {
                using (SqlCommand cmd = connection.CreateCommand())
                {
                    cmd.CommandText = @"SELECT TOP(@Limit) * FROM users JOIN DriversLicenses ON Users.id=DriversLicenses.user_id;";

                    SqlParameter p = new SqlParameter("@Limit", System.Data.SqlDbType.Int);
                    p.Value = limit;
                    cmd.Parameters.Add(p);
                    int received_i = 0;
                    connection.Open();
                    using (SqlDataReader reader = cmd.ExecuteReader())
                    {
                        while (reader.Read())
                        {
                            { // Always encrypted is not enabled here, but it is on the column in the database. Therefore we obtain the raw bytes from the database, encrypted under the database CEK
                                int id = reader.GetInt32(reader.GetOrdinal("id"));
                                int bsn = reader.GetInt32(reader.GetOrdinal("bsn"));
                                string firstname = reader.GetString(reader.GetOrdinal("firstname"));
                                string lastname = reader.GetString(reader.GetOrdinal("lastname"));
                                DateTime birth_date = reader.GetDateTime(reader.GetOrdinal("birth_date"));
                                string birth_place = reader.GetString(reader.GetOrdinal("birth_place"));
                                string postal_code = reader.GetString(reader.GetOrdinal("postal_code"));
                                string house_nr = reader.GetString(reader.GetOrdinal("house_nr"));

                                int drivers_license_id = reader.GetInt32(reader.GetOrdinal("drivers_license_id"));
                                DateTime assigned = reader.GetDateTime(reader.GetOrdinal("assigned"));
                                DateTime expired = reader.GetDateTime(reader.GetOrdinal("expired"));
                                int penalty_points = reader.GetInt32(reader.GetOrdinal("penalty_points"));

                                TestPrint("AE lastname: " + lastname);
                                received_i++;
                            }

                        }
                        reader.Close();
                    }
                    TestPrint("Done receiving data (" + received_i + "/" + limit + ")");
                }
            }

            TestPrint("");
        }


        List<string> insert_firstnames = new List<string>();
        List<string> insert_lastnames = new List<string>();
        List<string> insert_birthdates = new List<string>();
        List<string> insert_birthplaces = new List<string>();
        List<string> insert_postalcodes = new List<string>();
        List<string> insert_housenrs = new List<string>();
        [IterationSetup(Targets = new[] { nameof(TestAE_InsertRow), nameof(TestAE_InsertRow2) })]
        public void Setup_TestAE_InsertRow()
        {
            for (int i = 0; i < max_insert_rows; i++)
            {
                insert_firstnames.Add(RandomStringOfLength(6));
                insert_lastnames.Add(RandomStringOfLength(8));
                insert_birthdates.Add(RandomDate());
                insert_birthplaces.Add(RandomStringOfLength(10));
                insert_postalcodes.Add(RandomStringOfLength(6));
                insert_housenrs.Add(this.random.Next(1, 1000) + "");
            }
        }

        [GlobalCleanup(Targets = new[] { nameof(TestAE_InsertRow), nameof(TestAE_InsertRow2) })]
        public void Cleanup_TestAE_InsertRow()
        {
            insert_firstnames.Clear();
            insert_lastnames.Clear();
            insert_birthdates.Clear();
            insert_birthplaces.Clear();
            insert_postalcodes.Clear();
            insert_housenrs.Clear();
        }


        [Benchmark]
        [ArgumentsSource(nameof(TryInsertAmounts))]
        public void TestAE_InsertRow(int insert_amount)
        {
            TestPrint("AE inserting row");

            using (SqlConnection connection = new SqlConnection(connectionStringAE))
            {
                connection.Open();

                for (int i = 0; i < insert_amount; i++)
                {
                    using (SqlCommand cmd = connection.CreateCommand())
                    {
                        cmd.CommandText = @"INSERT dbo.Users ([BSN], [firstname], [lastname], [birth_date], [birth_place], [postal_code], [house_nr]) VALUES (@BSN, @FirstName, @LastName, @BirthDate, @Birthplace, @PostalCode, @HouseNr); SELECT CAST(scope_identity() AS int)";

                        cmd.Parameters.AddWithValue("@BSN", 1100000 + i);
                        cmd.Parameters.AddWithValue("@FirstName", insert_firstnames[i]);
                        SqlParameter plastname = new SqlParameter(parameterName: "@LastName", System.Data.SqlDbType.VarChar);
                        plastname.Value = insert_lastnames[i];
                        cmd.Parameters.Add(plastname);
                        cmd.Parameters.AddWithValue("@BirthDate", insert_birthdates[i]);
                        cmd.Parameters.AddWithValue("@Birthplace", insert_birthplaces[i]);
                        SqlParameter ppostalcode = new SqlParameter("@PostalCode", System.Data.SqlDbType.VarChar);
                        ppostalcode.Value = insert_postalcodes[i];
                        cmd.Parameters.Add(ppostalcode);
                        cmd.Parameters.AddWithValue("@HouseNr", insert_housenrs[i]);


                        var result = cmd.ExecuteScalar();
                        if (result != null)
                        {
                            int user_id = (Int32)result;
                            TestPrint("Inserted user with id: " + user_id);
                        }
                        else
                        {

                        }
                    }
                }
            }


            TestPrint("");

        }


        // Again, but using a transaction
        [Benchmark]
        [ArgumentsSource(nameof(TryInsertAmounts))]
        public void TestAE_InsertRow2(int insert_amount)
        {
            TestPrint("AE inserting row with transaction");

            using (SqlConnection connection = new SqlConnection(connectionStringAE))
            {
                connection.Open();
                SqlTransaction transaction = connection.BeginTransaction();

                for (int i = 0; i < insert_amount; i++)
                {
                    using (SqlCommand cmd = connection.CreateCommand())
                    {
                        cmd.Transaction = transaction;
                        cmd.CommandText = @"INSERT dbo.Users ([BSN], [firstname], [lastname], [birth_date], [birth_place], [postal_code], [house_nr]) VALUES (@BSN, @FirstName, @LastName, @BirthDate, @Birthplace, @PostalCode, @HouseNr); SELECT CAST(scope_identity() AS int)";

                        cmd.Parameters.AddWithValue("@BSN", 1100000 + i);
                        cmd.Parameters.AddWithValue("@FirstName", insert_firstnames[i]);
                        SqlParameter plastname = new SqlParameter(parameterName: "@LastName", System.Data.SqlDbType.VarChar);
                        plastname.Value = insert_lastnames[i];
                        cmd.Parameters.Add(plastname);
                        cmd.Parameters.AddWithValue("@BirthDate", insert_birthdates[i]);
                        cmd.Parameters.AddWithValue("@Birthplace", insert_birthplaces[i]);
                        SqlParameter ppostalcode = new SqlParameter("@PostalCode", System.Data.SqlDbType.VarChar);
                        ppostalcode.Value = insert_postalcodes[i];
                        cmd.Parameters.Add(ppostalcode);
                        cmd.Parameters.AddWithValue("@HouseNr", insert_housenrs[i]);


                        var result = cmd.ExecuteScalar();
                        if (result != null)
                        {
                            int user_id = (Int32)result;
                            TestPrint("Inserted user with id: " + user_id);
                        }
                        else
                        {

                        }
                    }
                }

                transaction.Commit();
            }


            TestPrint("");

        }





        /**************** PRE tests ****************/
        /*
         * The various PRE functions re-use the same test code, since they only
         * differ in the supplied connection string and internal working.
         */



        public IEnumerable<object[]> Arguments_GetPlainColumns()
        {
            foreach (var limit in TryLimits())
            {
                yield return new object[] { limit, "Column Encryption PRE Setting=Bidirectional" };
                yield return new object[] { limit, "Column Encryption PRE Setting=BidirectionalTEE" };
            }
        }

        [Benchmark]
        [ArgumentsSource(nameof(Arguments_GetPlainColumns))]
        public void TestPRE_GetPlainColumns(int limit, string PREsetting)
        {
            TestPrint("PRE (" + PREsetting + ") getting 3 plain columns");

            using (SqlConnection connection = new SqlConnection(connectionStringAE + PREsetting))
            {
                using (SqlCommand cmd = connection.CreateCommand())
                {
                    cmd.CommandText = @"SELECT TOP(@Limit) id, firstname, birth_place FROM users";

                    SqlParameter p = new SqlParameter("@Limit", System.Data.SqlDbType.Int);
                    p.Value = limit;
                    cmd.Parameters.Add(p);
                    int received_i = 0;
                    connection.Open();
                    using (SqlDataReader reader = cmd.ExecuteReader())
                    {
                        while (reader.Read())
                        {
                            {

                                int id_string = reader.GetInt32(reader.GetOrdinal("id"));
                                string firstname_string = reader.GetString(reader.GetOrdinal("firstname"));
                                string birth_place_string = reader.GetString(reader.GetOrdinal("birth_place"));

                                TestPrint("PRE firstname: " + firstname_string);
                                received_i++;
                            }

                        }
                        reader.Close();
                    }
                    TestPrint("Done receiving data (" + received_i + "/" + limit + ")");
                }
            }


            TestPrint("");
        }

        public IEnumerable<object[]> Arguments_GetEncryptedColumns()
        {
            byte[] encryptedSymmetricKey = rsa_proxy.Encrypt(aes_client.Key, RSAEncryptionPadding.OaepSHA256);
            byte[] encryptedSymmetricIV = rsa_proxy.Encrypt(aes_client.IV, RSAEncryptionPadding.OaepSHA256);
            byte[] publickeyBytesClient = Encoding.UTF8.GetBytes(rsa_client.ExportSubjectPublicKeyInfoPem());

            foreach (var limit in TryLimits())
            {
                yield return new object[] { limit, "Column Encryption PRE Setting=" + "Bidirectional", publickeyBytesClient, encryptedSymmetricKey, encryptedSymmetricIV };
                yield return new object[] { limit, "Column Encryption PRE Setting=" + "BidirectionalTEE", publickeyBytesClient, encryptedSymmetricKey, encryptedSymmetricIV };
            }
        }

        [Benchmark]
        [ArgumentsSource(nameof(Arguments_GetEncryptedColumns))]
        public void TestPRE_GetEncryptedColumns(int limit, string PREsetting, byte[] public_key_client, byte[] enc_symmetric_key, byte[] enc_symmetric_IV)
        {
            TestPrint("PRE (" + PREsetting + ") getting 3 encrypted columns");

            using (SqlConnection connection = new SqlConnection(connectionStringAE + PREsetting))
            {
                using (SqlCommand cmd = connection.CreateCommand())
                {
                    cmd.CommandText = @"SELECT TOP(@Limit) bsn, lastname, postal_code FROM users";
                    cmd.PREPublicKey = public_key_client;
                    cmd.PREEncryptedSymmetricKey = enc_symmetric_key;
                    cmd.PREEncryptedSymmetricIV = enc_symmetric_IV;

                    SqlParameter p = new SqlParameter("@Limit", System.Data.SqlDbType.Int);
                    p.Value = limit;
                    cmd.Parameters.Add(p);

                    int received_i = 0;

                    connection.Open();
                    using (SqlDataReader reader = cmd.ExecuteReader())
                    {
                        while (reader.Read())
                        {
                            { // Always encrypted is not enabled here, but it is on the column in the database. Therefore we obtain the raw bytes from the database, encrypted under the database CEK
                                byte[] bsn = (byte[])reader.GetValue(reader.GetOrdinal("bsn"));
                                byte[] lastname = (byte[])reader.GetValue(reader.GetOrdinal("lastname"));
                                byte[] postal_code = (byte[])reader.GetValue(reader.GetOrdinal("postal_code"));

                                string lastname_string = Convert.ToBase64String(lastname);
                                TestPrint("PRE bsn (encoded): " + lastname_string);
                                received_i++;
                            }

                        }
                        reader.Close();
                    }
                    TestPrint("Done receiving data ("  + received_i + "/" + limit + ")");
                }
            }

            TestPrint("");
        }

        public IEnumerable<object[]> Arguments_GetWherePlain()
        {
            byte[] encryptedSymmetricKey = rsa_proxy.Encrypt(aes_client.Key, RSAEncryptionPadding.OaepSHA256);
            byte[] encryptedSymmetricIV = rsa_proxy.Encrypt(aes_client.IV, RSAEncryptionPadding.OaepSHA256);
            byte[] publickeyBytesClient = Encoding.UTF8.GetBytes(rsa_client.ExportSubjectPublicKeyInfoPem());


            yield return new object[] { "Column Encryption PRE Setting=" + "Bidirectional", publickeyBytesClient, encryptedSymmetricKey, encryptedSymmetricIV };
            yield return new object[] { "Column Encryption PRE Setting=" + "BidirectionalTEE", publickeyBytesClient, encryptedSymmetricKey, encryptedSymmetricIV };
        }

        [Benchmark]
        [ArgumentsSource(nameof(Arguments_GetWherePlain))]
        public void TestPRE_GetWherePlain(string PREsetting, byte[] public_key_client, byte[] enc_symmetric_key, byte[] enc_symmetric_IV, int query_id = 3)
        {
            TestPrint("PRE (" + PREsetting + ") getting columns where plain");

            using (SqlConnection connection = new SqlConnection(connectionStringAE + PREsetting))
            {
                using (SqlCommand cmd = connection.CreateCommand())
                {
                    cmd.CommandText = @"SELECT * FROM users WHERE id = @Id";
                    cmd.PREPublicKey = public_key_client;
                    cmd.PREEncryptedSymmetricKey = enc_symmetric_key;
                    cmd.PREEncryptedSymmetricIV = enc_symmetric_IV;

                    SqlParameter p2 = new SqlParameter("@Id", System.Data.SqlDbType.Int);
                    p2.Value = query_id;
                    cmd.Parameters.Add(p2);

                    int received_i = 0;

                    connection.Open();
                    using (SqlDataReader reader = cmd.ExecuteReader())
                    {
                        while (reader.Read())
                        {
                            { // Always encrypted is not enabled here, but it is on the column in the database. Therefore we obtain the raw bytes from the database, encrypted under the database CEK
                                int id = reader.GetInt32(reader.GetOrdinal("id"));
                                byte[] bsn = (byte[])reader.GetValue(reader.GetOrdinal("bsn"));
                                string firstname = reader.GetString(reader.GetOrdinal("firstname"));
                                byte[] lastname = (byte[])reader.GetValue(reader.GetOrdinal("lastname"));
                                DateTime birth_date = reader.GetDateTime(reader.GetOrdinal("birth_date"));
                                string birth_place = reader.GetString(reader.GetOrdinal("birth_place"));
                                byte[] postal_code = (byte[])reader.GetValue(reader.GetOrdinal("postal_code"));
                                string house_nr = reader.GetString(reader.GetOrdinal("house_nr"));

                                string lastname_string = Convert.ToBase64String(lastname);
                                TestPrint("PRE lastname (encoded): " + lastname_string);
                                received_i++;
                            }

                        }
                        reader.Close();
                    }
                    TestPrint("Done receiving data (" + received_i + ")");
                }
            }

            TestPrint("");
        }

        public IEnumerable<object[]> Arguments_GetWhereEncrypted()
        {
            byte[] encryptedSymmetricKey = rsa_proxy.Encrypt(aes_client.Key, RSAEncryptionPadding.OaepSHA256);
            byte[] encryptedSymmetricIV = rsa_proxy.Encrypt(aes_client.IV, RSAEncryptionPadding.OaepSHA256);
            byte[] publickeyBytesClient = Encoding.UTF8.GetBytes(rsa_client.ExportSubjectPublicKeyInfoPem());

            byte[] bsn_3_encrypted = aes_client.EncryptCbc(new byte[] { 3, 0, 0, 0 }, aes_client.IV);


            yield return new object[] { "Column Encryption PRE Setting=" + "Bidirectional", publickeyBytesClient, encryptedSymmetricKey, encryptedSymmetricIV, bsn_3_encrypted };
            yield return new object[] { "Column Encryption PRE Setting=" + "BidirectionalTEE", publickeyBytesClient, encryptedSymmetricKey, encryptedSymmetricIV, bsn_3_encrypted };
        }

        [Benchmark]
        [ArgumentsSource(nameof(Arguments_GetWhereEncrypted))]
        public void TestPRE_GetWhereEncrypted(string PREsetting, byte[] public_key_client, byte[] enc_symmetric_key, byte[] enc_symmetric_IV, byte[] value)
        {
            TestPrint("PRE (" + PREsetting + ") getting columns where encrypted");

            using (SqlConnection connection = new SqlConnection(connectionStringAE + PREsetting))
            {
                using (SqlCommand cmd = connection.CreateCommand())
                {
                    cmd.CommandText = @"SELECT * FROM users WHERE bsn = @BSN";
                    cmd.PREPublicKey = public_key_client;
                    cmd.PREEncryptedSymmetricKey = enc_symmetric_key;
                    cmd.PREEncryptedSymmetricIV = enc_symmetric_IV;
                    cmd.CommandTimeout = 120; // Required for when db has 10 million entries

                    SqlParameter p2 = new SqlParameter("@BSN", System.Data.SqlDbType.Int);
                    p2.Value = value; // The client encrypted value
                    cmd.Parameters.Add(p2);

                    int received_i = 0;

                    connection.Open();
                    using (SqlDataReader reader = cmd.ExecuteReader())
                    {
                        while (reader.Read())
                        {

                            { // Always encrypted is not enabled here, but it is on the column in the database. Therefore we obtain the raw bytes from the database, encrypted under the database CEK
                                int id = reader.GetInt32(reader.GetOrdinal("id"));
                                byte[] bsn = (byte[])reader.GetValue(reader.GetOrdinal("bsn"));
                                string firstname = reader.GetString(reader.GetOrdinal("firstname"));
                                byte[] lastname = (byte[])reader.GetValue(reader.GetOrdinal("lastname"));
                                DateTime birth_date = reader.GetDateTime(reader.GetOrdinal("birth_date"));
                                string birth_place = reader.GetString(reader.GetOrdinal("birth_place"));
                                byte[] postal_code = (byte[])reader.GetValue(reader.GetOrdinal("postal_code"));
                                string house_nr = reader.GetString(reader.GetOrdinal("house_nr"));

                                string lastname_string = Convert.ToBase64String(lastname);
                                TestPrint("PRE lastname (encoded): " + lastname_string);
                                received_i++;
                            }

                        }

                        TestPrint("Done reading results");
                        reader.Close();
                    }
                    TestPrint("Done receiving data (" + received_i + ")");
                }
            }

            TestPrint("");
        }


        public IEnumerable<object[]> Arguments_GetJoinPlain()
        {
            byte[] encryptedSymmetricKey = rsa_proxy.Encrypt(aes_client.Key, RSAEncryptionPadding.OaepSHA256);
            byte[] encryptedSymmetricIV = rsa_proxy.Encrypt(aes_client.IV, RSAEncryptionPadding.OaepSHA256);
            byte[] publickeyBytesClient = Encoding.UTF8.GetBytes(rsa_client.ExportSubjectPublicKeyInfoPem());

            foreach (var limit in TryLimits())
            {
                yield return new object[] { limit, "Column Encryption PRE Setting=" + "Bidirectional", publickeyBytesClient, encryptedSymmetricKey, encryptedSymmetricIV };
                yield return new object[] { limit, "Column Encryption PRE Setting=" + "BidirectionalTEE", publickeyBytesClient, encryptedSymmetricKey, encryptedSymmetricIV };
            }
        }

        [Benchmark]
        [ArgumentsSource(nameof(Arguments_GetJoinPlain))]
        public void TestPRE_GetJoinPlain(int limit, string PREsetting, byte[] public_key_client, byte[] enc_symmetric_key, byte[] enc_symmetric_IV)
        {
            TestPrint("PRE (" + PREsetting + ") getting columns joined on plain");
            ;

            using (SqlConnection connection = new SqlConnection(connectionStringAE + PREsetting))
            {
                using (SqlCommand cmd = connection.CreateCommand())
                {
                    cmd.CommandText = @"SELECT TOP(@Limit) * FROM users JOIN DriversLicenses ON Users.id=DriversLicenses.user_id;";
                    cmd.PREPublicKey = public_key_client;
                    cmd.PREEncryptedSymmetricKey = enc_symmetric_key;
                    cmd.PREEncryptedSymmetricIV = enc_symmetric_IV;

                    SqlParameter p = new SqlParameter("@Limit", System.Data.SqlDbType.Int);
                    p.Value = limit;
                    cmd.Parameters.Add(p);

                    int received_i = 0;

                    connection.Open();
                    using (SqlDataReader reader = cmd.ExecuteReader())
                    {
                        while (reader.Read())
                        {
                            { // Always encrypted is not enabled here, but it is on the column in the database. Therefore we obtain the raw bytes from the database, encrypted under the database CEK
                                int id = reader.GetInt32(reader.GetOrdinal("id"));
                                byte[] bsn = (byte[])reader.GetValue(reader.GetOrdinal("bsn"));
                                string firstname = reader.GetString(reader.GetOrdinal("firstname"));
                                byte[] lastname = (byte[])reader.GetValue(reader.GetOrdinal("lastname"));
                                DateTime birth_date = reader.GetDateTime(reader.GetOrdinal("birth_date"));
                                string birth_place = reader.GetString(reader.GetOrdinal("birth_place"));
                                byte[] postal_code = (byte[])reader.GetValue(reader.GetOrdinal("postal_code"));
                                string house_nr = reader.GetString(reader.GetOrdinal("house_nr"));

                                int drivers_license_id = reader.GetInt32(reader.GetOrdinal("drivers_license_id"));
                                DateTime assigned = reader.GetDateTime(reader.GetOrdinal("assigned"));
                                DateTime expired = reader.GetDateTime(reader.GetOrdinal("expired"));
                                int penalty_points = reader.GetInt32(reader.GetOrdinal("penalty_points"));


                                string lastname_string = Convert.ToBase64String(lastname);
                                TestPrint("PRE lastname (encoded): " + lastname_string);
                                received_i++;
                            }

                        }
                        reader.Close();
                    }
                    TestPrint("Done receiving data (" + received_i + "/" + limit + ")");
                }
            }

            TestPrint("");

        }



        List<byte[]> insert_bsn_pre = new List<byte[]>();
        List<string> insert_firstnames_pre = new List<string>();
        List<byte[]> insert_lastnames_pre = new List<byte[]>();
        List<string> insert_birthdates_pre = new List<string>();
        List<string> insert_birthplaces_pre = new List<string>();
        List<byte[]> insert_postalcodes_pre = new List<byte[]>();
        List<string> insert_housenrs_pre = new List<string>();
        [IterationSetup(Targets = new[] { nameof(TestPRE_InsertRow), nameof(TestPRE_InsertRow2) })]
        public void Setup_TestPRE_InsertRow()
        {
            for (int i = 0; i < max_insert_rows; i++)
            {
                insert_bsn_pre.Add(aes_client.EncryptCbc(BitConverter.GetBytes(1100000 + i), aes_client.IV));
                insert_firstnames_pre.Add(RandomStringOfLength(6));
                insert_lastnames_pre.Add(aes_client.EncryptCbc(Encoding.UTF8.GetBytes(RandomStringOfLength(8)), aes_client.IV));
                insert_birthdates_pre.Add(RandomDate());
                insert_birthplaces_pre.Add(RandomStringOfLength(10));
                insert_postalcodes_pre.Add(aes_client.EncryptCbc(Encoding.UTF8.GetBytes(RandomStringOfLength(6)), aes_client.IV));
                insert_housenrs_pre.Add(this.random.Next(1, 1000) + "");
            }
        }

        [IterationCleanup(Targets = new[] { nameof(TestPRE_InsertRow), nameof(TestPRE_InsertRow2) })]
        public void Cleanup_TestPRE_InsertRow()
        {
            insert_bsn_pre.Clear();
            insert_firstnames_pre.Clear();
            insert_lastnames_pre.Clear();
            insert_birthdates_pre.Clear();
            insert_birthplaces_pre.Clear();
            insert_postalcodes_pre.Clear();
            insert_housenrs_pre.Clear();
        }

        public IEnumerable<object[]> Arguments_TestPRE_InsertRow()
        {
            byte[] encryptedSymmetricKey = rsa_proxy.Encrypt(aes_client.Key, RSAEncryptionPadding.OaepSHA256);
            byte[] encryptedSymmetricIV = rsa_proxy.Encrypt(aes_client.IV, RSAEncryptionPadding.OaepSHA256);
            byte[] publickeyBytesClient = Encoding.UTF8.GetBytes(rsa_client.ExportSubjectPublicKeyInfoPem());

            foreach (var amount in TryInsertAmounts())
            {
                yield return new object[] { amount, "Column Encryption PRE Setting=" + "Bidirectional", publickeyBytesClient, encryptedSymmetricKey, encryptedSymmetricIV };
                yield return new object[] { amount, "Column Encryption PRE Setting=" + "BidirectionalTEE", publickeyBytesClient, encryptedSymmetricKey, encryptedSymmetricIV };
            }
        }

        [Benchmark]
        [ArgumentsSource(nameof(Arguments_TestPRE_InsertRow))]
        public void TestPRE_InsertRow(int insert_amount, string PREsetting, byte[] public_key_client, byte[] enc_symmetric_key, byte[] enc_symmetric_IV)
        {
            TestPrint("PRE inserting row");

            using (SqlConnection connection = new SqlConnection(connectionStringAE + PREsetting))
            {
                connection.Open();

                for (int i = 0; i < insert_amount; i++)
                {
                    using (SqlCommand cmd = connection.CreateCommand())
                    {
                        cmd.CommandText = @"INSERT dbo.Users ([BSN], [firstname], [lastname], [birth_date], [birth_place], [postal_code], [house_nr]) VALUES (@BSN, @FirstName, @LastName, @BirthDate, @Birthplace, @PostalCode, @HouseNr); SELECT CAST(scope_identity() AS int)";
                        cmd.PREPublicKey = public_key_client;
                        cmd.PREEncryptedSymmetricKey = enc_symmetric_key;
                        cmd.PREEncryptedSymmetricIV = enc_symmetric_IV;


                        SqlParameter pbsn = new SqlParameter(parameterName: "@BSN", System.Data.SqlDbType.Int);
                        pbsn.Value = insert_bsn_pre[i];
                        cmd.Parameters.Add(pbsn);
                        cmd.Parameters.AddWithValue("@FirstName", insert_firstnames_pre[i]);
                        SqlParameter plastname = new SqlParameter(parameterName: "@LastName", System.Data.SqlDbType.VarChar);
                        plastname.Value = insert_lastnames_pre[i];
                        cmd.Parameters.Add(plastname);
                        cmd.Parameters.AddWithValue("@BirthDate", insert_birthdates_pre[i]);
                        cmd.Parameters.AddWithValue("@Birthplace", insert_birthplaces_pre[i]);
                        SqlParameter ppostalcode = new SqlParameter("@PostalCode", System.Data.SqlDbType.VarChar);
                        ppostalcode.Value = insert_postalcodes_pre[i];
                        cmd.Parameters.Add(ppostalcode);
                        cmd.Parameters.AddWithValue("@HouseNr", insert_housenrs_pre[i]);


                        var result = cmd.ExecuteScalar();
                        if (result != null)
                        {
                            int user_id = (Int32)result;
                            TestPrint("Inserted user with id: " + user_id);
                        }
                        else
                        {

                        }
                    }

                }
            }


            TestPrint("");

        }



        // Again, but with a transaction
        [Benchmark]
        [ArgumentsSource(nameof(Arguments_TestPRE_InsertRow))]
        public void TestPRE_InsertRow2(int insert_amount, string PREsetting, byte[] public_key_client, byte[] enc_symmetric_key, byte[] enc_symmetric_IV)
        {
            TestPrint("PRE inserting row with transaction");

            using (SqlConnection connection = new SqlConnection(connectionStringAE + PREsetting))
            {
                connection.Open();
                SqlTransaction transction = connection.BeginTransaction();

                for (int i = 0; i < insert_amount; i++)
                {
                    using (SqlCommand cmd = connection.CreateCommand())
                    {
                        cmd.Transaction = transction;
                        cmd.CommandText = @"INSERT dbo.Users ([BSN], [firstname], [lastname], [birth_date], [birth_place], [postal_code], [house_nr]) VALUES (@BSN, @FirstName, @LastName, @BirthDate, @Birthplace, @PostalCode, @HouseNr); SELECT CAST(scope_identity() AS int)";
                        cmd.PREPublicKey = public_key_client;
                        cmd.PREEncryptedSymmetricKey = enc_symmetric_key;
                        cmd.PREEncryptedSymmetricIV = enc_symmetric_IV;


                        SqlParameter pbsn = new SqlParameter(parameterName: "@BSN", System.Data.SqlDbType.Int);
                        pbsn.Value = insert_bsn_pre[i];
                        cmd.Parameters.Add(pbsn);
                        cmd.Parameters.AddWithValue("@FirstName", insert_firstnames_pre[i]);
                        SqlParameter plastname = new SqlParameter(parameterName: "@LastName", System.Data.SqlDbType.VarChar);
                        plastname.Value = insert_lastnames_pre[i];
                        cmd.Parameters.Add(plastname);
                        cmd.Parameters.AddWithValue("@BirthDate", insert_birthdates_pre[i]);
                        cmd.Parameters.AddWithValue("@Birthplace", insert_birthplaces_pre[i]);
                        SqlParameter ppostalcode = new SqlParameter("@PostalCode", System.Data.SqlDbType.VarChar);
                        ppostalcode.Value = insert_postalcodes_pre[i];
                        cmd.Parameters.Add(ppostalcode);
                        cmd.Parameters.AddWithValue("@HouseNr", insert_housenrs_pre[i]);


                        var result = cmd.ExecuteScalar();
                        if (result != null)
                        {
                            int user_id = (Int32)result;
                            TestPrint("Inserted user with id: " + user_id);
                        }
                        else
                        {

                        }
                    }

                }
                transction.Commit();
            }


            TestPrint("");

        }




        /**************** Utilities ****************/

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


        private void TestPrint(string msg)
        {
            if (this.debug)
            {
                Console.WriteLine(msg);
            }
        }
        private void TestPrint(string template, string value)
        {
            if (this.debug)
            {
                Console.WriteLine(template, value);
            }
        }


        /*
         * Empty the database and reset auto increment identity to 0.
         */
        public void ClearDatabase()
        {
            Console.WriteLine("Clearing database...");
            using (SqlConnection connection = new SqlConnection(connectionStringAE))
            {
                // TRUNCATE does not work due to foreign key constraints, thus DELETE
                // Also reset auto increment identity to 0
                SqlCommand cmd = connection.CreateCommand();
                cmd.CommandText = @"DELETE FROM DriversLicenseCodes; DELETE FROM DriversLicenses; DELETE FROM Users;DBCC CHECKIDENT (DriversLicenseCodes, RESEED, 0);DBCC CHECKIDENT (DriversLicenses, RESEED, 0);DBCC CHECKIDENT (Users, RESEED, 0)";

                connection.Open();
                cmd.ExecuteNonQuery();
            }
            Console.WriteLine("Done clearing database!");

        }


        /*
         * Count the amount of rows in the User table.
         * Return -1 on error.
         */
        public int GetUserRowsCount()
        {
            using (SqlConnection connection = new SqlConnection(connectionStringAE))
            {
                connection.Open();


                using (SqlCommand cmd = connection.CreateCommand())
                {
                    cmd.CommandText = @"SELECT count(*) FROM users;";

                    var result = cmd.ExecuteScalar();
                    if (result != null)
                    {
                        int rows_count = (Int32)result;
                        TestPrint("Amount of rows currently in database: " + rows_count);
                        return rows_count;
                    }
                }
            }

            return -1;
        }

        /*
         * Random data generation
         */
        const string RandomStringOfLength_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        public string RandomStringOfLength(int length)
        {
            return new string(Enumerable.Repeat(RandomStringOfLength_chars, length).Select(s => s[this.random.Next(s.Length)]).ToArray());
        }

        const string RandomCode_chars = "ABCD";
        public string RandomCode()
        {
            return new string(Enumerable.Repeat(RandomCode_chars, 1).Select(s => s[this.random.Next(s.Length)]).ToArray());
        }

        public string RandomDate()
        {
            // Be safe, only go to day 28
            return string.Format("{0}-{1}-{2}", this.random.Next(1900, 2020), this.random.Next(1, 12), this.random.Next(1, 28));
        }

        /*
         * Add 'rows' rows to the database, using randomly generated data.
         * Possibly with start and end index.
         */
        public void InitializeDatabase(int rows)
        {
            InitializeDatabase(0, rows);
        }
        public void InitializeDatabase(int start, int end)
        {
            Console.WriteLine("Initializing database with " + end + " rows...");
            using (SqlConnection connection = new SqlConnection(connectionStringAE))
            {
                connection.Open();

                for (int i = start; i < end; i++)
                {
                    if (i % 1000 == 0)
                    {
                        Console.WriteLine("Initializing database status (" + Math.Round((i * 100.0) / end, 2) + "%) at (" + i + "/" + end + ") rows...");
                    }
                    int user_id;
                    using (SqlCommand cmd = connection.CreateCommand())
                    {
                        cmd.CommandText = @"INSERT dbo.Users ([BSN], [firstname], [lastname], [birth_date], [birth_place], [postal_code], [house_nr]) VALUES (@BSN, @FirstName, @LastName, @BirthDate, @Birthplace, @PostalCode, @HouseNr); SELECT CAST(scope_identity() AS int)";

                        cmd.Parameters.AddWithValue("@BSN", i);
                        cmd.Parameters.AddWithValue("@FirstName", RandomStringOfLength(6));
                        SqlParameter plastname = new SqlParameter(parameterName: "@LastName", System.Data.SqlDbType.VarChar);
                        plastname.Value = RandomStringOfLength(8);
                        cmd.Parameters.Add(plastname);
                        cmd.Parameters.AddWithValue("@BirthDate", RandomDate());
                        cmd.Parameters.AddWithValue("@Birthplace", RandomStringOfLength(10));
                        SqlParameter ppostalcode = new SqlParameter("@PostalCode", System.Data.SqlDbType.VarChar);
                        ppostalcode.Value = RandomStringOfLength(6);
                        cmd.Parameters.Add(ppostalcode);
                        cmd.Parameters.AddWithValue("@HouseNr", this.random.Next(1000) + "");



                        var result = cmd.ExecuteScalar();
                        if (result != null)
                        {
                            user_id = (Int32)result;
                        }
                        else
                        {
                            continue;
                        }
                    }
                    int drivers_license_id;
                    using (SqlCommand cmd = connection.CreateCommand())
                    {
                        cmd.CommandText = @"INSERT dbo.DriversLicenses ([user_id], [assigned], [expired], [penalty_points]) VALUES (@UserID, @Assigned, @Expired, @PenaltyPoints); SELECT CAST(scope_identity() AS int)";

                        cmd.Parameters.AddWithValue("@UserID", user_id);
                        cmd.Parameters.AddWithValue("@Assigned", RandomDate());
                        cmd.Parameters.AddWithValue("@Expired", RandomDate());
                        cmd.Parameters.AddWithValue("@PenaltyPoints", this.random.Next(2));

                        var result = cmd.ExecuteScalar();
                        if (result != null)
                        {
                            drivers_license_id = (Int32)result;
                        }
                        else
                        {
                            continue;
                        }
                    }
                    int drivers_license_code_id;
                    using (SqlCommand cmd = connection.CreateCommand())
                    {
                        cmd.CommandText = @"INSERT dbo.DriversLicenseCodes ([drivers_license_id], [code], [extra]) VALUES (@DriversLicenseID, @Code, @Extra); SELECT CAST(scope_identity() AS int)";

                        cmd.Parameters.AddWithValue("@DriversLicenseID", drivers_license_id);
                        cmd.Parameters.AddWithValue("@Code", RandomCode());
                        cmd.Parameters.AddWithValue("@Extra", "");

                        var result = cmd.ExecuteScalar();
                        if (result != null)
                        {
                            drivers_license_code_id = (Int32)result;
                        }
                        else
                        {
                            continue;
                        }
                    }
                }

            }
            Console.WriteLine("Done initializing database!");

        }





        /*
         * Add the percentile columns to the benchmark results.
         * Also present all measurements in milliseconds.
         */
        private class Config : ManualConfig
        {
            public Config()
            {
                AddColumn(
                    StatisticColumn.P0,
                    StatisticColumn.P90,
                    StatisticColumn.P95,
                    StatisticColumn.P100);

                this.WithSummaryStyle(SummaryStyle.Default.WithTimeUnit(Perfolizer.Horology.TimeUnit.Millisecond));
            }
        }









    }





}
