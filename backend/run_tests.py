"""Run only the listed offline fixture suites; never launch the guard or apps."""
from pathlib import Path
import subprocess,sys
HERE=Path(__file__).resolve().parent
commands=[
    [sys.executable,'-B','-m','unittest','discover','-s',str(HERE/'tests'),'-p','test_*.py'],
    [sys.executable,'-B','-m','unittest','discover','-s',str(HERE/'source/native-launcher'),'-p','test_*.py'],
    [sys.executable,'-B','-m','unittest','discover','-s',str(HERE/'source/privacy-qa'),'-p','test_status_publisher.py'],
    [sys.executable,'-B','-m','unittest','discover','-s',str(HERE/'source/privacy-qa'),'-p','test_browser_service_preflight.py'],
    ['node','--test',str(HERE/'source/privacy-qa/claude_environment_controller.test.mjs'),str(HERE/'source/privacy-qa/status_publisher.test.mjs')],
]
if __name__=='__main__':
    for command in commands:
        p=subprocess.run(command,cwd=HERE.parent,timeout=180)
        if p.returncode:sys.exit(p.returncode)
