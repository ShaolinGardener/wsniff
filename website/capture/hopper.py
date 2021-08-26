from abc import ABC, abstractmethod
from threading import Thread, Event
import random
import time
from enum import Enum
from functools import reduce

random.seed()


class _ChannelStatistics():
    """
    Encapsulate the information how many new APs were found on which channels
    since the last channel hop and between which channels should be hopped.
    """
    def __init__(self, channels:list):
        """
        channels: a list of channels you want to switch between
        """
        #should be a sorted list since that is expected by some strategies
        self.channels = sorted(channels)
        self.stats = dict()

    def num_channels(self):
        return len(self.channels)
    
    def get_channels(self):
        return self.channels

    def get_count(self, channel:int):
        """
        Returns how many new APs were found on that channel since the last hop
        """
        return self.stats.get(channel, 0)

    def increment_count(self, channel:int):
        """
        Should be called if a new AP was found on this channel
        """
        self.stats[channel] = self.stats.get(channel, 0) + 1

    def reset_count(self, channel:int):
        """
        Should be called after a hop was executed
        """
        self.stats.clear()



class HoppingStrategy(ABC):
    """
    interface needed to implement the strategy pattern in order to pass hopping strategies
    to a hopper object
    """

    def set_num_interfaces(self, num_interfaces:int):
        """
        set the number of interfaces that are available
        """
        self.num_interfaces = num_interfaces

    @abstractmethod
    def get_hop(self, channel_stats:_ChannelStatistics) -> list:
        """
        Returns a list of channels you should switch to next

        num_interfaces: the number of interfaces that are available for hopping
        channel_stats: a dict {(channel, num-new-APs)} which contains for every
        channel the number of new APs that have been discovered since the last hop
        """
        pass

    @abstractmethod
    def get_delay(self, channel_stats:_ChannelStatistics) -> list:
        """
        Returns a delay that should pass until the channels are switched again
        """
        pass


class ChaosHoppingStrategy(HoppingStrategy):
    """
    Just switches channels completely randomly and waits a fixed time span 
    between two hops. Two interfaces can even be on the same channel.
    """

    def __init__(self, delay):
        """
        delay: the time span to wait between two hops
        """
        super().__init__()
        self.delay = delay
    
    def get_hop(self, channel_stats:_ChannelStatistics):
        #choices will pick k random elements WITH replacement (so it can pick values twice) 
        return random.choices(channel_stats.get_channels(), k=self.num_interfaces)

    def get_delay(self, channel_stats):
        return self.delay

class RandomStrategy(HoppingStrategy):
    """
    Switches randomly between channels and waits a fixed delay between two hops.
    Two interfaces will never be on the same channel. 
    One usecase could be that you have all channels covered with interfaces but want each channel
    to be listened to by different interfaces since your interfaces differ in their performance.
    """
    def __init__(self, delay):
        """
        delay: the time span to wait between two hops
        """
        super().__init__()
        self.delay = delay
    
    def get_hop(self, channel_stats:_ChannelStatistics):
        #sample will always return k UNIQUE elements of the list
        #NOTE: that means the number of interfaces has to be smaller than the number of channels  
        return random.sample(channel_stats.get_channels(), k=self.num_interfaces)

    def get_delay(self, channel_stats):
        return self.delay

class EvenlyDistributedHopping(HoppingStrategy):
    """
    The channel distance will be maximized here in order to prevent channel overlapping and 
    therefore trying to maximize the number of siffed beacons.
    Switching the channels will be random
    """
    def __init__(self, delay):
        super().__init__()
        self.delay = delay
    
    def get_hop(self, channel_stats:_ChannelStatistics):
        step_width = round(channel_stats.num_channels()/float(self.num_interfaces))
        step_width = 1 if step_width==0 else step_width

        start = random.randint(0, channel_stats.num_channels()-1)
        source = channel_stats.get_channels()
        channels = list()

        for i in range(self.num_interfaces):
            index = (start + i*step_width) % len(source)
            channels.append(source[index])
        return channels

    def get_delay(self, channel_stats):
        return self.delay

class FOCC(HoppingStrategy):
    
    class State(Enum):
        LEARN = 1
        EXPERIENCE = 2

    def __init__(self, t_learn: float, t_exp: float, generations:int=3):
        """
        Prefer channels which have shown in the past that they are inhabited by more APs.
        To prevent starving and take in new information, use a timeslot procedure with 
        2 types of timeslots:
        - one in which the channel is selected based on experience
            (sniff for t_exp seconds)
        - one in which the channel is selected randomly 
            (sniff for t_learn seconds - choose a rather long value for the strategy to work)

        generations: take the last <generations> channel statistics into account for computing 
            the new channels. Newer stats will have higher impact/weight than older ones.
        """

        super().__init__()

        self.generations
        self.t_learn = t_learn
        self.t_exp = t_exp
        self.state = FOCC.State.LEARN

        self.history = dict()

    
    def get_hop(self, channel_stats:_ChannelStatistics):
        channels = channel_stats.get_channels()

        if self.state == FOCC.State.LEARN:
            return random.sample(channels, k=self.num_interfaces) 
        elif self.state == FOCC.State.EXPERIENCE:
            #update weights based on new stats and compute weights
            weights = list()
            for channel in channels:
                #get number of new APs on that channel
                t = channel_stats.get_count(channel)
                #get history list for this channel
                ch_hist = self.history.get(channel, list())
                ch_hist.append(t)

                #if necessary, remove old information
                if len(ch_hist) > self.generations:
                    ch_hist.pop(0)

                #now compute weight for channel based on channel history
                #first in the list are old values
                counter = len(ch_hist)
                def _relevance_func(x):
                    #weigh newer values stronger than older ones
                    nonlocal counter
                    weight = (1./counter)*(x/1.75)
                    counter -= 1
                    return weight

                #compute relevance factor for each point in history and sum up values
                weight = reduce((lambda x, y: x+y) , map(_relevance_func, ch_hist))
                weights.append(weight)

            return random.choices(channels, weights=weights, k=self.num_interfaces)
        else:
            #should not occur
            pass

    def get_delay(self, channel_stats):
        #remember: this methods is called AFTER the current state/timeslot is already over
        #so you have to choose the delay for the FOLLOWING timeslot/state
        if self.state == FOCC.State.LEARN:
            self.state = FOCC.State.EXPERIENCE
            return self.t_exp
        else: #self.state==FOCC.State.EXPERIENCE
            self.state = FOCC.State.LEARN 
            return self.t_learn

class Hopper(Thread):
    """
    A class that takes takes interfaces and executes the hopping between 802.11 channels
    based on the strategy defined by a given hopping strategy.
    """

    def __init__(self, hop_strategy: HoppingStrategy, interfaces:list, channels:list):
        """
        hop_strategy: strategy by which the next channels and delay are decided
        interfaces: the interfaces that should be used for hopping/capturing data
        channels: a list of channels between which the interfaces should hop
        """
        Thread.__init__(self)
        self.interfaces = interfaces
        self.channels = channels

        self.hop_strategy = hop_strategy
        self.hop_strategy.set_num_interfaces(len(interfaces))

        self.stop = Event()

        #init channel stats
        self.channel_stats = _ChannelStatistics()

    def increment_ap_observations(self, channel: int):
        """
        whenever a new AP is discovered, this method should be called to update the
        channel count of the corresponding channel

        channel: the channel on which a new AP was found
        """
        self.channel_stats.increment_count(channel)

    def run(self):
        while True:
            if self.stop.is_set():
                break
            
            #execute one hopping round
            channels = self.hop_strategy.get_hop(self.channel_stats)
            for i in range(len(channels)):
                self.interfaces[i].set_channel(channels[i])

            delay = self.hop_strategy.get_delay(self.channel_stats)
            #reset channel stats
            self.channel_stats.reset()

            #delay till next hop
            time.sleep(delay)

    def stop(self):
        """
        Stop the channel hopping. After this, this object has done its job. 
        If you need to hop channels again, create a new Hopper-object.
        """
        self.stop.set()

