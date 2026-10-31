"""Installation-specific ceiling. Empty source distribution fails closed.

backend/configure.py generates this file in the freshly built output directory,
using the operator's validated public IPv4 list and residential server address.
Never edit the author's active installation or reuse their private parameters.
"""
ALLOWED = frozenset()
PRIMARY = ''
