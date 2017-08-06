using System.Net.Sockets;

namespace Fuckshadows.Controller
{
    public partial class Listener
    {
        public abstract class Service : IService
        {
            public abstract bool Handle(ServiceUserToken token);

            public abstract void Stop();
        }
    }
}
