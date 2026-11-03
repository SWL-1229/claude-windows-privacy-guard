from pathlib import Path
import sys,ctypes,time
ROOT=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT/'privacy-qa'))
import environment_lease as leases
import brave_browser_launch
if __name__=='__main__':
    try:brave_browser_launch.main(ROOT)
    except Exception as error:
        code=getattr(error,'code',None) or str(error)
        if not isinstance(code,str) or len(code)>100 or not all(c.isalnum() or c=='_' for c in code):code='protected_brave_start_failed'
        leases.atomic_json(ROOT/'brave-browser-last-failure.json',{'schema':1,'code':code,'at':time.time()})
        ctypes.windll.user32.MessageBoxW(None,'Brave 专用环境未通过核验：'+code+'。原 Edge 入口和登录资料保留；没有改用其他出口。','Claude Brave 隐私环境',0x30)
