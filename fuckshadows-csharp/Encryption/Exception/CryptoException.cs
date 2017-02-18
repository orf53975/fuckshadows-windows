namespace Fuckshadows.Encryption.Exception
{
    public class CryptoNeedMoreException : System.Exception
    {
        public CryptoNeedMoreException()
        {
        }

        public CryptoNeedMoreException(string msg) : base(msg)
        {
        }

        public CryptoNeedMoreException(string message, System.Exception innerException) : base(message, innerException)
        {
        }
    }

    public class CryptoErrorException : System.Exception
    {
        public CryptoErrorException()
        {
        }

        public CryptoErrorException(string msg) : base(msg)
        {
        }

        public CryptoErrorException(string message, System.Exception innerException) : base(message, innerException)
        {
        }
    }
}