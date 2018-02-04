using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using Fuckshadows.Encryption.AEAD;
using Fuckshadows.Encryption.Stream;
using Microsoft.VisualBasic;

namespace Fuckshadows.Encryption
{
    public static class EncryptorFactory
    {
        private static Dictionary<string, Type> _registeredEncryptors = new Dictionary<string, Type>();

        private static readonly Type[] ConstructorTypes = {typeof(string), typeof(string)};

        static EncryptorFactory()
        {
            var AEADMbedTLSEncryptorSupportedCiphers = AEADMbedTLSEncryptor.SupportedCiphers();
            var AEADSodiumEncryptorSupportedCiphers = AEADSodiumEncryptor.SupportedCiphers();
            if (Sodium.AES256GCMAvailable)
            {
                // prefer to aes-256-gcm in libsodium
                AEADMbedTLSEncryptorSupportedCiphers.Remove("aes-256-gcm");
            }
            else
            {
                AEADSodiumEncryptorSupportedCiphers.Remove("aes-256-gcm");
            }

            // XXX: sequence matters, OpenSSL > Sodium > MbedTLS
            foreach (string method in StreamOpenSSLEncryptor.SupportedCiphers())
            {
                if (!_registeredEncryptors.ContainsKey(method))
                    _registeredEncryptors.Add(method, typeof(StreamOpenSSLEncryptor));
            }

            foreach (string method in StreamSodiumEncryptor.SupportedCiphers())
            {
                if (!_registeredEncryptors.ContainsKey(method))
                    _registeredEncryptors.Add(method, typeof(StreamSodiumEncryptor));
            }

            foreach (string method in StreamMbedTLSEncryptor.SupportedCiphers())
            {
                if (!_registeredEncryptors.ContainsKey(method))
                    _registeredEncryptors.Add(method, typeof(StreamMbedTLSEncryptor));
            }


            foreach (string method in AEADOpenSSLEncryptor.SupportedCiphers())
            {
                if (!_registeredEncryptors.ContainsKey(method))
                    _registeredEncryptors.Add(method, typeof(AEADOpenSSLEncryptor));
            }

            foreach (string method in AEADSodiumEncryptorSupportedCiphers)
            {
                if (!_registeredEncryptors.ContainsKey(method))
                    _registeredEncryptors.Add(method, typeof(AEADSodiumEncryptor));
            }

            foreach (string method in AEADMbedTLSEncryptorSupportedCiphers)
            {
                if (!_registeredEncryptors.ContainsKey(method))
                    _registeredEncryptors.Add(method, typeof(AEADMbedTLSEncryptor));
            }
        }

        public static IEncryptor GetEncryptor(string method, string password)
        {
            if (method.IsNullOrEmpty())
            {
                method = "aes-256-cfb";
            }

            method = method.ToLowerInvariant();
            var t = _registeredEncryptors[method];

            ConstructorInfo c = t.GetConstructor(ConstructorTypes);
            if (c == null) throw new System.Exception("Invalid ctor");
            IEncryptor result = (IEncryptor) c.Invoke(new object[] {method, password});
            return result;
        }
    }
}