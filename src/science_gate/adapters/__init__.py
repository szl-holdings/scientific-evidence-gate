"""Citation resolver adapters (ARCHITECTURE.md sections 9 and 17.14).

``frozen`` answers from recorded resolver responses, canary records included,
and never touches the network. ``live`` (content negotiation for metadata)
and ``doi_handle`` (Handle body codes for the live canary) are the only code
in the package allowed to open a network connection, and they do so only when
``NetworkPolicy.live`` is true, through ``NetworkPolicy.opener`` only. The
resolver adapters return the same
:class:`~science_gate.adapters.records.Resolution` shape, so a live answer is
judged by exactly the rules a frozen one is, and both kinds of negative
control come back as a :class:`~science_gate.adapters.records.CanaryCheck`.
"""
