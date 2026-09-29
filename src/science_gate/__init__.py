"""scientific-evidence-gate: an evidence gate for scientific artifacts.

The governing rule is that a passing check must emit enough evidence to prove
that it had the opportunity to fail. This package establishes integrity and
declared-evaluation facts only; it never establishes scientific validity.
"""

__version__ = "0.1.0"

#: Distribution name, recorded in receipts so a reader can tell which tool
#: produced them without trusting the file name.
TOOL_NAME = "scientific-evidence-gate"
