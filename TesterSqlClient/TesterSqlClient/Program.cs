// See https://aka.ms/new-console-template for more information
using Azure.Core;
using BenchmarkDotNet.Running;
using Microsoft.Data.SqlClient;
using Microsoft.SqlServer.Server;
using System.Collections;
using System.Configuration;
using System.Security.Cryptography;
using System.Text;
using TesterSqlClient;

Tests tests = new Tests(true);
//tests.TestAll();
tests.ClearDatabase();
tests.InitializeDatabase(10000000);

//var summary = BenchmarkRunner.Run<Tests>();



