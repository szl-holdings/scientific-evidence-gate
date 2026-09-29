"""Citation resolver adapters (ARCHITECTURE.md section 9).

``frozen`` answers from recorded resolver responses and never touches the
network. ``live`` is the only code in the package allowed to open a network
connection, and it may do so only when ``NetworkPolicy.live`` is true.

STUB: a later stage implements both adapters.
"""
