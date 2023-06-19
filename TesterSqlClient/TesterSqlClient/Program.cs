// See https://aka.ms/new-console-template for more information
using BenchmarkDotNet.Running;
using TesterSqlClient;

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




Tests tests = new Tests(true);
tests.TestSingle();
//tests.TestAll();


//tests.ClearDatabase();
//tests.InitializeDatabase(1000); // Initialize database with N rows
//tests.InitializeDatabase(915284, 1000000); // Add rows i until N to the database (resume initializing)

//var summary = BenchmarkRunner.Run<Tests>();

