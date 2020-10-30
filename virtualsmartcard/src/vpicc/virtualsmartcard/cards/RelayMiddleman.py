from functools import reduce

def id(x):
    return x

def compose(outer,inner):
    return lambda x: outer(inner(x))

class RelayMiddleman(object):
    """
    The RelayMiddleman class serves as a base from which a user might derive
    their own relay middle man class.  It may also be used directly to create
    stateless Middlemen.  When instantiated without arguments, this class 
    implements the simplest Man-in-the-Middle:  the NoOp.
    """

    def __init__(self,inTransformer=None,inDispatch=None,
                 outTransformer=None,outDispatch=None):
        """
        A RelayMiddleman object may be optionally initialized with callables
        (PDU -> PDU/None), which are used in the handleInPDU and handleOutPDU methods.
        [in/out]Transormers need to be productive, as their result is passed on.
        Transormers may be used to alter the packets transmitted via the Middleman.
        [in/out]Dispatchers do not need to be productive, as their result is
        discarded.  They may be used to extract information from the stream of packets
        (i.e. logging).
        
        This initializer may safely be completly overwritten by a child class.
        The default implementations of handleInPDU and handleOutPDU works without
        initialization.
        """
        if inTransformer:  self.inTransformer  = inTransformer  
        if inDispatch:     self.inDispatch     = inDispatch
        if outTransformer: self.outTransformer = outTransformer 
        if outDispatch:    self.outDispatch    = outDispatch

    def handleInPDU(self, inPDU: bytes):
        """
        This method is called on each PDU that is fed into the relay (vdpu -> vicc).
        It may be overwritten to modify the packages send from the terminal to the 
        real smart card.  If it is not overwritten it will try to apply the content of
        the inTransformer and inDispatch attributes to the argument PDU and passes on the result.
        If such attributes do no exist it will simply pass on the PDU unchanged.
        """
        getattr(self,'inDispatch',id)(inPDU)
        return getattr(self,'inTransformer',id)(inPDU)

    def handleOutPDU(self, outPDU: bytes):
        """
        This method is called on each PDU that is produced by the relay (vicc -> vdpu).
        It may be overwritten to modify the packages send from the real smart card to the
        terminal.  If it is not overwritten it will try to apply the content of
        the outTransformer and outDispatch attributes to the argument PDU and passes on the result.
        If such attributes do not exist it will simply pass on the PDU unchanged.
        """
        getattr(self,'outDispatch',id)(outPDU)
        return getattr(self,'outTransformer',id)(outPDU)

def composeMitMs(mitms):
    """
    This function takes an interable of Middlemen and composes them into a single one.
    Conceptually, for a list of MitMs [front,...,back] the result looks as follows: 
    Reader <-> front <-> ... <-> back <-> Smartcard
    Therefore the flow of execution is as follows:
      --> front.handleInPDU  -> ... -> back.handleInPDU  ---
      |                                                    |
      |                                                    v
    Reader                                             Smartcard
      ^                                                    |
      |                                                    |
      --- front.handleOutPDU <- ... <- back.handleOutPDU <--
    """
    inComposition = reduce(compose,reversed([mitm.handleInPDU for mitm in mitms]),id)
    outComposition = reduce(compose,[mitm.handleOutPDU for mitm in mitms],id)
    return RelayMiddleman(inTransformer = inComposition, outTransformer = outComposition)

def ConsoleLogger(name="",inp="In",out="Out"):
    """
    Returns a MitM which logs the relayed packets to the console using print.
    This MitM is mainly intended to be used in conjunction with composeMitMs
    to debug MitMs.  The name, inp and out parameters may be used to create a
    custom prefix that is printed before the packet, which is useful when multiple
    ConsoleLoggers are used.
    (i.e. composeMitMs([ConsoleLogger("ReaderSide"),buggyMitM,ConsoleLogger("CardSide")]))
    """
    inpPrefix = "-".join(t for t in [name,inp] if t)
    outPrefix = "-".join(t for t in [name,out] if t)
    def prefixedPrint(prefix,pdu):
        start = f"{prefix}: " if prefix else ""
        print(f"{start}{pdu}")
    return RelayMiddleman(inDispatch = lambda ipdu: prefixedPrint(inpPrefix,ipdu),
                          outDispatch = lambda opdu: prefixedPrint(outPrefix,opdu))
