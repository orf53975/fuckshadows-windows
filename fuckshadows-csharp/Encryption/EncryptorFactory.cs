using System;
using System.Collections.Generic;
using System.Reflection;
using Fuckshadows.Encryption.Stream;

namespace Fuckshadows.Encryption
{
    public static class EncryptorFactory
    {
        private static Dictionary<string, Type> _registeredEncryptors = new Dictionary<string, Type>();

        private static Type[] _constructorTypes = new Type[] {typeof(string), typeof(string)};

        static EncryptorFactory()
        {
            foreach (string method in StreamMbedTLSEncryptor.SupportedCiphers())
            {
                _registeredEncryptors.Add(method, typeof(StreamMbedTLSEncryptor));
            }
            foreach (string method in StreamSodiumEncryptor.SupportedCiphers())
            {
                _registeredEncryptors.Add(method, typeof(StreamSodiumEncryptor));
            }
            // TODO: add AEAD ciphers
        }

        public static IEncryptor GetEncryptor(string method, string password)
        {
            if (method.IsNullOrEmpty())
            {
                method = "aes-256-cfb";
            }
            method = method.ToLowerInvariant();
            Type t = _registeredEncryptors[method];
            ConstructorInfo c = t.GetConstructor(_constructorTypes);
            if (c == null) throw new System.Exception("Invalid ctor");
            IEncryptor result = (IEncryptor) c.Invoke(new object[] {method, password});
            return result;
        }
    }
}