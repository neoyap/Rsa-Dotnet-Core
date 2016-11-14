using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;
using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace ConsoleApp1
{
    public class Program
    {
        // 规范
        //http://blog.csdn.net/linda1000/article/details/8676330
        //https://en.wikipedia.org/wiki/RSA_(cryptosystem)
        //https://www.w3.org/PICS/DSig/RSA-MD5_1_0.html
        // Referenace 
        //http://www.cnblogs.com/dudu/p/dotnet-core-rsa-openssl.html
        //https://gist.github.com/Jargon64/5b172c452827e15b21882f1d76a94be4/
        //http://stackoverflow.com/questions/243646/how-to-read-a-pem-rsa-private-key-from-net
        //http://www.jensign.com/JavaScience/dotnet/SignFileHash/SignFilehash.txt
        //https://github.com/onovotny/BouncyCastle-PCL/blob/pcl/crypto/test/src/openssl/test/AllTests.cs
        //https://raw.githubusercontent.com/neoeinstein/bouncycastle/master/crypto/src/security/DotNetUtilities.cs
        //https://referencesource.microsoft.com/#mscorlib/system/security/cryptography/utils.cs,f90b02ed5ab87a1c
        //http://www.lai18.com/content/3497693.html
        //http://stackoverflow.com/questions/12512455/rsa-key-xml-format-compatible-for-net  <--have to look this
        //http://blog.csdn.net/qq387732471/article/details/6800488 not work, but bring next link
        //http://blog.csdn.net/qq387732471/article/details/6800388
        //http://www.cnblogs.com/isaboy/p/csharp_openssl_rsa_jsencrypt.html?utm_source=tuicool&utm_medium=referral
        // core foundation is provide the source code
        //https://referencesource.microsoft.com/#mscorlib/system/security/cryptography/rsacryptoserviceprovider.cs
        //https://referencesource.microsoft.com/mscorlib/system/runtime/compilerservices/jithelpers.cs.html#42f2478cbfe5a17b

        //openssl genrsa -out rsa_1024_priv.pem 1024
        //private static readonly string _privateKey = @"MIICXgIBAAKBgQC0xP5HcfThSQr43bAMoopbzcCyZWE0xfUeTA4Nx4PrXEfDvybJEIjbU/rgANAty1yp7g20J7+wVMPCusxftl/d0rPQiCLjeZ3HtlRKld+9htAZtHFZosV29h/hNE9JkxzGXstaSeXIUIWquMZQ8XyscIHhqoOmjXaCv58CSRAlAQIDAQABAoGBAJtDgCwZYv2FYVk0ABw6F6CWbuZLUVykks69AG0xasti7Xjh3AximUnZLefsiuJqg2KpRzfv1CM+Cw5cp2GmIVvRqq0GlRZGxJ38AqH9oyUa2m3TojxWapY47zyePYEjWwRTGlxUBkdujdcYj6/dojNkm4azsDXl9W5YaXiPfbgJAkEA4rlhSPXlohDkFoyfX0v2OIdaTOcVpinv1jjbSzZ8KZACggjiNUVrSFV3Y4oWom93K5JLXf2mV0Sy80mPR5jOdwJBAMwciAk8xyQKpMUGNhFX2jKboAYY1SJCfuUnyXHAPWeHp5xCL2UHtjryJp/Vx8TgsFTGyWSyIE9R8hSup+32rkcCQBe+EAkC7yQ0np4Z5cql+sfarMMm4+Z9t8b4N0a+EuyLTyfs5Dtt5JkzkggTeuFRyOoALPJP0K6M3CyMBHwb7WsCQQCiTM2fCsUO06fRQu8bO1A1janhLz3K0DU24jw8RzCMckHE7pvhKhCtLn+n+MWwtzl/L9JUT4+BgxeLepXtkolhAkEA2V7er7fnEuL0+kKIjmOm5F3kvMIDh9YC1JwLGSvu1fnzxK34QwSdxgQRF1dfIKJw73lClQpHZfQxL/2XRG8IoA==".Replace("\n", "");
        //openssl rsa -pubout -in rsa_1024_priv.pem -out rsa_1024_pub.pem
        //private static readonly string _publicKey = @"MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC0xP5HcfThSQr43bAMoopbzcCyZWE0xfUeTA4Nx4PrXEfDvybJEIjbU/rgANAty1yp7g20J7+wVMPCusxftl/d0rPQiCLjeZ3HtlRKld+9htAZtHFZosV29h/hNE9JkxzGXstaSeXIUIWquMZQ8XyscIHhqoOmjXaCv58CSRAlAQIDAQAB".Replace("\n", "");

        /*
            OpenSSL> genrsa -out rsa_private_key.pem   1024  #Gen Private Key
            OpenSSL> pkcs8 -topk8 -inform PEM -in rsa_private_key.pem -outform PEM -nocrypt -out rsa_private_key_pkcs8.pem #Java developer usually in PKCS8 format
            OpenSSL> rsa -in rsa_private_key.pem -pubout -out rsa_public_key.pem #Gen Public Key
         */
        private static readonly string _privateKey = @"MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAIZaRouD0ESme7+vFefIW5aCyrjJWt1mkA5ITWfHHsFbZ8ErIWFTaysr95aLWIdHkEoBUi0lNKwnlQdPV0/X5XNTJK03o/u+52424ppinZbog2nDSWYeuAwTe2zipdGB9COwJ/7TIgJyTLhXfxAax7l6FxKmP6oXK7SJk5Ln5ZAlAgMBAAECgYBSatC5xxuc8XAab4KFlFAy7XsEjmjSRpd6W3o4flrsjHECe73XYX/tlOQmEsc0/X6TF2pczWUZcpKmUFKkZTGYgM4qku0qimu9rsbMNFrro0R0weV2sq2sShRzN9qTXbDv/6ze6jn1gzDCSEAsb0LLtTQMJ2jH9zPm7tRzK8qAoQJBALr+EkQxZxDMe/TD7l15lFWH+DZPMGC9X7ZSafICzdgJu+XPAQiDOVFmtd/hEIF9ee7ifhc1Zf4NZy4QQGdrQT0CQQC37xvGZdrsteWaNrKFQFVkG+zJ4gProhR1QDUB1LGOny+avL5mi+nbghJ7XwfI7NqFPYzTUjmNp3lVm5IGO6kJAkAk9fdyVzmCDokp1liVTWTOizO6uGhdltEGXr/mQDujyjjDsekIX7fCqUSl3fy/O6gQWeCGgd2JG+kbJ8czKfYZAkB0UuTm8S2mPFdL00HNoeUfHcX/20+NawCzMnsTgFcWkrgBjVKA+gVZDIbxvSToPlronwd78elyG7NRn8SW6o45AkEAtB0nGH5YKXIS07CoQMRBHoXx4f+ojofNoJvzI5Ax+ZBbSx/z5hTSm/jN7llVFRE+3rRyNLigX/r2O4vVkprHTg==".Replace("\n", "");
        
        //private static readonly string _publicKey = @"MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCGWkaLg9BEpnu/rxXnyFuWgsq4yVrdZpAOSE1nxx7BW2fBKyFhU2srK/eWi1iHR5BKAVItJTSsJ5UHT1dP1+VzUyStN6P7vuduNuKaYp2W6INpw0lmHrgME3ts4qXRgfQjsCf+0yICcky4V38QGse5ehcSpj+qFyu0iZOS5+WQJQIDAQAB";//.Replace("\n", "");
        
        public static void Main(string[] args)
        {            
            var plainText         = "test16";//fIMKJ5Sz8EGIenkb39dzJUGkPiNgF9WpKuYDXW3snnqgDFa9TdxvhhXjBJUEvT38so41PSuFGw9XQOW4ddaP5qUt90IotV6Z3NBvEE/ApNNqhucza0cI3vS6nNPEGP7S7+PS/eCtLfDCUimSwJM2WXoKxswZlQwP7QmF4Wz0CoI=
            byte[] plainTextBytes = Encoding.UTF8.GetBytes(plainText);
            var privateKey        = PemToXml("-----BEGIN PRIVATE KEY-----\r\n" + _privateKey + "\r\n-----END PRIVATE KEY-----");
            RSA rsa               = RSA.Create(); rsa.FromXmlString(privateKey);
            RSAParameters Key     = rsa.ExportParameters(true);
            byte[] signData       = rsa.SignData(plainTextBytes, HashAlgorithmName.MD5, RSASignaturePadding.Pkcs1); // pkcs8 / md5
            string sign           = Convert.ToBase64String(signData);
            byte[] signData2      = rsa.Encrypt(plainTextBytes, RSAEncryptionPadding.Pkcs1); // pkcs1 / asn1 
            string sign2          = Convert.ToBase64String(signData2);
            Console.WriteLine(sign);
            Console.ReadLine();
        } 
        public static string PemToXml(string pem)
        {
            if (pem.StartsWith("-----BEGIN RSA PRIVATE KEY-----")
                || pem.StartsWith("-----BEGIN PRIVATE KEY-----"))
            {
                return GetXmlRsaKey(pem, obj =>
                {
                    if ((obj as RsaPrivateCrtKeyParameters) != null)
                        return DotNetUtilities.ToRSA((RsaPrivateCrtKeyParameters)obj);
                    var keyPair = (AsymmetricCipherKeyPair)obj;
                    return DotNetUtilities.ToRSA((RsaPrivateCrtKeyParameters)keyPair.Private);
                }, rsa => rsa.ToXmlString(true));
            }

            if (pem.StartsWith("-----BEGIN PUBLIC KEY-----"))
            {
                return GetXmlRsaKey(pem, obj =>
                {
                    var publicKey = (RsaKeyParameters)obj;
                    return DotNetUtilities.ToRSA(publicKey);
                }, rsa => rsa.ToXmlString(false));
            }

            throw new InvalidKeyException("Unsupported PEM format...");
        }
        private static string GetXmlRsaKey(string pem, Func<object, RSA> getRsa, Func<RSA, string> getKey)
        {
            using (var ms = new MemoryStream())
            using (var sw = new StreamWriter(ms))
            using (var sr = new StreamReader(ms))
            {
                sw.Write(pem);
                sw.Flush();
                ms.Position = 0;
                var pr = new PemReader(sr);
                object keyPair = pr.ReadObject();
                using (RSA rsa = getRsa(keyPair))
                {
                    var xml = getKey(rsa);
                    return xml;
                }
            }
        }
    }
}

