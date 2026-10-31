"""Candidate-only restoration of an existing minimized native monitor window.

No lease is renewed here. The normal watchdog must independently read fresh
nonce-bound metadata on its next pass. Does not replace a dead monitor.
"""
import json
import subprocess
import time


class NativeMinimizeRecovery:
    COOLDOWN_SECONDS = 10.0

    def __init__(self, target, nonce, *, helper, alive, still_current,
                 runner=subprocess.run, clock=time.monotonic):
        self.target = dict(target)
        self.nonce = nonce
        self.helper = helper
        self.alive = alive
        self.still_current = still_current
        self.runner = runner
        self.clock = clock
        self.attempted = False
        self.next_allowed_at = 0.0

    def verified(self):
        # Only the normal real-metadata path may reset an episode. It does not
        # reset the independent monotonic cooldown after repeated minimize use.
        self.attempted = False

    def _command(self, command, *extra):
        result = self.runner([str(self.helper()), command, str(self.target['pid']),
                              self.target['creation'], *map(str, extra)],
                             capture_output=True, text=True, encoding='utf-8-sig',
                             timeout=3, creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
        if result.returncode or len(result.stdout) > 32768:
            return None
        value = json.loads(result.stdout)
        if (type(value) is not dict or value.get('ok') is not True
                or value.get('command') != command or value.get('pid') != self.target['pid']
                or type(value.get('data')) is not dict):
            return None
        return value['data']

    def try_after_revocation(self, reason):
        """Caller must already have published an invalid lease for this pass."""
        if reason != 'native_environment_unavailable':
            return False
        now = self.clock()
        if self.attempted or now < self.next_allowed_at:
            return False
        # Mark before any potentially failing query: no retry storm on malformed
        # output, a closed inspector, ambiguous windows or unavailable UIA.
        self.attempted = True
        self.next_allowed_at = now + self.COOLDOWN_SECONDS
        try:
            if self.alive(self.target) is not True or self.still_current() is not True:
                return False
            observed = self._command('inspect')
            if type(observed) is not dict or type(observed.get('windows')) is not list:
                return False
            recognized = [w for w in observed['windows']
                          if type(w) is dict and w.get('kind') in
                          ('devtools-claude', 'devtools-error-page')]
            if len(recognized) != 1:
                return False
            window = recognized[0]
            hwnd = window.get('hwnd')
            if (window.get('kind') != 'devtools-claude' or window.get('visible') is not True
                    or window.get('minimized') is not True or type(hwnd) is not int
                    or not 0 < hwnd < (1 << 63)):
                return False
            if self.alive(self.target) is not True or self.still_current() is not True:
                return False
            restored = self._command('recover-minimized-monitor', hwnd, self.nonce)
            return (type(restored) is dict and restored.get('recovered') is True
                    and restored.get('hwnd') == hwnd
                    and restored.get('foregroundPreserved') is True
                    and restored.get('ownMetadataPresent') is True
                    and restored.get('minimized') is False
                    and restored.get('visible') is True)
        except Exception:
            return False
