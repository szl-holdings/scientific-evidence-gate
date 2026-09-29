"""Citation resolver adapters (ARCHITECTURE.md section 9).

``frozen`` answers from recorded resolver responses and never touches the
network. ``live`` is the only code in the package allowed to open a network
connection, and it does so only when ``NetworkPolicy.live`` is true. Both
return the same :class:`~science_gate.adapters.records.Resolution` shape, so
a live answer is judged by exactly the rules a frozen one is.
"""
