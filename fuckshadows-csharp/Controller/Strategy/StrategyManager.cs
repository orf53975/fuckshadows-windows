using System.Collections.Generic;

namespace Fuckshadows.Controller.Strategy
{
    class StrategyManager
    {
        List<IStrategy> _strategies;
        public StrategyManager(FuckshadowsController controller)
        {
            _strategies = new List<IStrategy>();
            _strategies.Add(new BalancingStrategy(controller));
            _strategies.Add(new HighAvailabilityStrategy(controller));
            _strategies.Add(new StatisticsStrategy(controller));
            // TODO: load DLL plugins
        }
        public IList<IStrategy> GetStrategies()
        {
            return _strategies;
        }
    }
}
