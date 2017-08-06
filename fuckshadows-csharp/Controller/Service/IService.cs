using System;

namespace Fuckshadows.Controller
{
    public interface IService
    {
        /*
         * chain of responsibility
         * If one service cannot handle, pass to next handler
         */
        bool Handle(ServiceUserToken token);

        /* close connections, dispose resources, etc */
        void Stop();
    }
}