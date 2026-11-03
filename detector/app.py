"""Native Windows desktop diagnostics. Run with pythonw; no web server."""
from pathlib import Path
import argparse
import datetime as dt
import json
import os
import queue
import sys
import threading
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

import checks
import monitor
import wfp_audit

HERE = Path(__file__).resolve().parent
COLORS = dict(bg='#F4F6F8', white='#FFFFFF', ink='#18283B', muted='#53657A', line='#DCE3EB',
              blue='#2059BA', green='#087A50', amber='#926000', red='#B52635')


class DetectorApp:
    def __init__(self, root, *, auto=True, guard_root=checks.ROOT):
        self.root=root
        self.guard_root=Path(guard_root)
        self.report=None
        self.busy=False
        self.events=queue.Queue()
        self.stop_event=threading.Event()
        self.refresh_event=threading.Event()
        self.monitor_started=False
        self.admin_review=wfp_audit.elevated()
        root.title('Claude 运行环境面板'+('（管理员只读核验）' if self.admin_review else ''))
        root.configure(bg=COLORS['bg'])
        root.geometry('1180x900')
        root.minsize(980,760)
        icon=HERE/'detector.ico'
        if icon.exists():
            root.iconbitmap(str(icon))
        self.hide_ip=tk.BooleanVar(value=False)
        self.export_hide=tk.BooleanVar(value=True)
        self.summary=tk.StringVar(value='正在连接原有监控…')
        self.activity=tk.StringVar(value='每秒更新 · 不增加公网探测，不修改保护。')
        self.filter=tk.StringVar(value='desktop')
        self.selection_key=None
        self.last_states=None
        self.style()
        outer=tk.Frame(root,bg=COLORS['bg'])
        outer.pack(fill='both',expand=True,padx=26,pady=20)
        header=tk.Frame(outer,bg=COLORS['bg'])
        header.pack(fill='x')
        tk.Label(header,text='Claude 运行环境',font=('Microsoft YaHei UI',23,'bold'),
                 bg=COLORS['bg'],fg=COLORS['ink']).pack(side='left')
        self.scan_btn=ttk.Button(header,text='刷新状态',style='Primary.TButton',command=self.scan)
        self.scan_btn.pack(side='right',ipadx=15,ipady=4)
        self.admin_btn=ttk.Button(header,text='重新核验内核' if self.admin_review else '管理员核验',command=self.request_admin_review)
        self.admin_btn.pack(side='right',padx=(0,8),ipady=4)
        tk.Label(outer,text='正在使用的安全环境，一眼看清。面板持续读取原有保护，不改变联网行为。',
                 bg=COLORS['bg'],fg=COLORS['muted'],font=('Microsoft YaHei UI',10),anchor='w').pack(fill='x',pady=(5,20))
        summary_frame=tk.Frame(outer,bg=COLORS['white'],highlightbackground=COLORS['line'],highlightthickness=1)
        summary_frame.pack(fill='x')
        self.metrics={}
        for column,(key,title) in enumerate([('exit','专用链路出口'),('desktop','Claude 桌面'),('browser','专用网页')]):
            summary_frame.columnconfigure(column,weight=1,uniform='summary')
            panel=tk.Frame(summary_frame,bg=COLORS['white'])
            panel.grid(row=0,column=column,sticky='nsew',padx=20,pady=16)
            tk.Label(panel,text=title,font=('Microsoft YaHei UI',10),fg=COLORS['muted'],bg=COLORS['white']).pack(anchor='w')
            label=tk.Label(panel,text='等待检测',font=('Microsoft YaHei UI',15,'bold'),fg=COLORS['ink'],bg=COLORS['white'],anchor='w',wraplength=280,justify='left')
            label.pack(fill='x',pady=(7,0))
            self.metrics[key]=label
        progress=tk.Frame(outer,bg=COLORS['bg'])
        progress.pack(fill='x',pady=(14,6))
        tk.Label(progress,textvariable=self.summary,bg=COLORS['bg'],fg=COLORS['ink'],font=('Microsoft YaHei UI',10,'bold')).pack(side='left')
        ttk.Checkbutton(progress,text='隐藏界面 IP',variable=self.hide_ip,command=self.refresh).pack(side='right')
        tabs=tk.Frame(outer,bg=COLORS['bg'])
        tabs.pack(fill='x',pady=(5,9))
        for key,title in [('desktop','Claude 桌面'),('browser','专用网页'),('all','全部监控')]:
            ttk.Radiobutton(tabs,text=title,value=key,variable=self.filter,command=self.refresh,style='Tab.TRadiobutton').pack(side='left',padx=(0,14))
        self.table_frame=tk.Frame(outer,bg=COLORS['white'])
        self.table_frame.pack(fill='both',expand=True)
        columns=('name','state','value','scope')
        self.table=ttk.Treeview(self.table_frame,columns=columns,show='headings',selectmode='browse',height=13)
        for name,title,width in [('name','检测项目',205),('state','结果',85),('value','检测值 / 状态',335),('scope','证据范围',255)]:
            self.table.heading(name,text=title,anchor='w')
            self.table.column(name,width=width,minwidth=65,stretch=name in ('value','scope'),anchor='w')
        bar=ttk.Scrollbar(self.table_frame,orient='vertical',command=self.table.yview)
        self.table.configure(yscrollcommand=bar.set)
        self.table.pack(side='left',fill='both',expand=True)
        bar.pack(side='right',fill='y')
        for state,color in [('pass',COLORS['green']),('unknown',COLORS['amber']),('fail',COLORS['red']),('off',COLORS['muted'])]:
            self.table.tag_configure(state,foreground=color)
        self.table.bind('<<TreeviewSelect>>',self.selected)
        detail_frame=tk.Frame(outer,bg=COLORS['white'],highlightbackground=COLORS['line'],highlightthickness=1)
        detail_frame.pack(fill='x',pady=(10,0))
        self.detail=tk.Text(detail_frame,height=3,wrap='word',font=('Microsoft YaHei UI',10),
                            relief='flat',bg=COLORS['white'],fg=COLORS['ink'],padx=12,pady=10,
                            selectbackground='#C7DAF8',state='disabled',cursor='arrow')
        self.detail.pack(fill='x')
        self.set_detail('从【Claude 安全联网】打开软件后，面板自动显示当前保护。\n绿色表示该项证据有效；策略状态与泄露实测分别说明。关闭面板不影响保护。')
        footer=tk.Frame(outer,bg=COLORS['bg'])
        footer.pack(fill='x',pady=(12,0))
        self.export_btn=ttk.Button(footer,text='导出报告',command=self.export,state='disabled')
        self.export_btn.pack(side='right')
        ttk.Checkbutton(footer,text='导出隐藏 IP',variable=self.export_hide).pack(side='right',padx=12)
        ttk.Button(footer,text='使用说明',command=self.help).pack(side='right')
        tk.Label(footer,textvariable=self.activity,font=('Microsoft YaHei UI',9),fg=COLORS['muted'],bg=COLORS['bg'],anchor='w').pack(side='left',fill='x',expand=True)
        # Reserve the evidence pane and controls before allocating the table.
        # This remains usable on smaller screens and at Windows 150% scaling.
        self.table_frame.pack_forget()
        detail_frame.pack_forget()
        footer.pack_forget()
        footer.pack(side='bottom',fill='x',pady=(12,0))
        detail_frame.pack(side='bottom',fill='x',pady=(10,0))
        self.table_frame.pack(fill='both',expand=True)
        root.bind('<F5>',lambda event:self.scan())
        root.protocol('WM_DELETE_WINDOW',self.close)
        root.after(150,self.poll)
        if auto:
            root.after(400,self.scan)

    def style(self):
        style=ttk.Style(self.root)
        style.theme_use('clam')
        style.configure('.',font=('Microsoft YaHei UI',10),background=COLORS['bg'],foreground=COLORS['ink'])
        style.configure('TButton',padding=(13,7),background=COLORS['white'],bordercolor=COLORS['line'])
        style.map('TButton',background=[('active','#E8EEF7')])
        style.configure('Primary.TButton',background=COLORS['blue'],foreground='white',font=('Microsoft YaHei UI',10,'bold'),borderwidth=0)
        style.map('Primary.TButton',background=[('disabled','#9CACC2'),('active','#164898')],foreground=[('disabled','#FFFFFF')])
        style.configure('Treeview',background=COLORS['white'],fieldbackground=COLORS['white'],rowheight=37,borderwidth=0,font=('Microsoft YaHei UI',10))
        style.configure('Treeview.Heading',background='#ECF0F5',foreground=COLORS['muted'],padding=(10,10),font=('Microsoft YaHei UI',10,'bold'),borderwidth=0)
        style.map('Treeview',background=[('selected','#DCE9FB')],foreground=[('selected',COLORS['ink'])])
        style.configure('Tab.TRadiobutton',padding=(2,7))

    def scan(self):
        self.refresh_event.set()
        if self.monitor_started:return
        self.monitor_started=True
        self.activity.set('正在连接原有保护监控…')
        def worker():
            try:
                live=monitor.LiveMonitor(self.guard_root)
                live.stream(lambda report:self.events.put(('done',report)),self.stop_event,self.refresh_event)
            except Exception as error:
                self.events.put(('error',checks.safe_code(error)))
        threading.Thread(target=worker,daemon=True).start()

    def request_admin_review(self):
        if self.admin_review:
            self.scan()
            return
        # Explicit UI action only; no background elevation, service install or
        # security-setting changes. Windows owns the UAC confirmation desktop.
        try:
            import ctypes,subprocess
            executable=Path(sys.executable).with_name('pythonw.exe')
            if not executable.is_file():raise OSError('pythonw_missing')
            args=subprocess.list2cmdline(['-E','-s','-B',str(HERE/'app.py'),'--admin-review','--root',str(self.guard_root)])
            shell=ctypes.WinDLL('shell32',use_last_error=True)
            shell.ShellExecuteW.argtypes=[ctypes.c_void_p,ctypes.c_wchar_p,ctypes.c_wchar_p,ctypes.c_wchar_p,ctypes.c_wchar_p,ctypes.c_int]
            shell.ShellExecuteW.restype=ctypes.c_void_p
            result=shell.ShellExecuteW(None,'runas',str(executable),args,str(HERE),1)
            if not result or result<=32:
                self.activity.set('管理员授权未完成；继续保留普通只读面板。')
                return
            self.close()  # Only this observer window; never the guard or Claude.
        except Exception:
            self.activity.set('无法打开管理员核验；原保护和当前面板仍保留。')

    def poll(self):
        try:
            while True:
                kind,value=self.events.get_nowait()
                if kind=='progress':self.activity.set(value)
                else:
                    self.busy=False
                    if kind=='done':
                        self.report=value
                        self.refresh()
                        self.export_btn.configure(state='normal')
                        self.activity.set('每秒更新 · 关闭面板不影响保护')
                    else:
                        self.summary.set('检测未完成')
                        self.activity.set('诊断代码：'+value)
                        self.monitor_started=False
        except queue.Empty:pass
        if self.report and not self.busy:
            current=tuple(checks.effective_state(item) for item in self.report['rows'])
            if current!=self.last_states:
                self.refresh()
        self.root.after(150,self.poll)

    def visible(self):
        return checks.export_report(self.report,hide_ip=self.hide_ip.get()) if self.report else None

    def refresh(self):
        data=self.visible()
        if not data:return
        self.last_states=tuple(item['state'] for item in data['rows'])
        selected=self.selection_key
        scroll=self.table.yview()
        wanted=[]
        states={k:0 for k in checks.STATES}
        for i,item in enumerate(data['rows']):
            states[item['state']]+=1
            if self.filter.get()!='all' and item['group'] not in ('network',self.filter.get()):continue
            wanted.append(item['key'])
            values=(item['name'],checks.STATES[item['state']],item['value'],item['source'])
            if self.table.exists(item['key']):self.table.item(item['key'],values=values,tags=(item['state'],))
            else:self.table.insert('', 'end', iid=item['key'],values=values,tags=(item['state'],))
        for key in self.table.get_children():
            if key not in wanted:self.table.delete(key)
        for index,key in enumerate(wanted):self.table.move(key,'',index)
        moment=dt.datetime.fromisoformat(data['finished_at']).astimezone().strftime('%H:%M:%S')
        self.summary.set(f"实时更新 {moment}    有效 {states['pass']} · 异常 {states['fail']} · 待验证 {states['unknown']} · 未运行 {states['off']}")
        for key in self.metrics:
            item=next((r for r in data['rows'] if r['key']=='exit'),None) if key=='exit' else next((r for r in data['rows'] if r['group']==key and 'runtime' in r['key']),None)
            if item:
                text=item['value'] if key=='exit' else '当前环境监控正常' if item['state']=='pass' else '尚未运行' if item['state']=='off' else '等待有效监控'
                if key=='exit' and item['state']!='pass':text='本次出口待验证'
                self.metrics[key].configure(text=text,fg={'pass':COLORS['green'],'fail':COLORS['red'],'unknown':COLORS['amber'],'off':COLORS['muted']}[item['state']])
        if selected and self.table.exists(selected):
            self.selected()
        elif self.table.get_children():
            self.table.selection_set(self.table.get_children()[0])
        if scroll:self.table.yview_moveto(scroll[0])

    def set_detail(self,text):
        self.detail.configure(state='normal')
        self.detail.delete('1.0','end')
        self.detail.insert('1.0',text)
        self.detail.configure(state='disabled')

    def selected(self,event=None):
        selected=self.table.selection()
        if not selected:return
        self.selection_key=selected[0]
        data=self.visible()
        item=next((v for v in data['rows'] if v['key']==self.selection_key),None)
        if item:
            when=dt.datetime.fromisoformat(item['measured_at']).astimezone().strftime('%Y-%m-%d %H:%M:%S %Z')
            extra='\n当前证据已过期，面板等待原监控更新。' if item['state']=='unknown' and next(v for v in self.report['rows'] if v['key']==item['key'])['state']=='pass' else ''
            self.set_detail(f"{item['name']}：{item['value']}\n{item['detail']}{extra}\n测量时间：{when}  |  来源：{item['source']}")

    def export(self):
        if not self.report:return
        path=filedialog.asksaveasfilename(parent=self.root,title='导出检测报告',defaultextension='.json',
                                         initialfile='Claude环境检测-'+dt.datetime.now().strftime('%Y%m%d-%H%M%S')+'.json',
                                         filetypes=[('JSON 检测报告','*.json')])
        if path:
            try:
                Path(path).write_text(json.dumps(checks.export_report(self.report,self.export_hide.get()),ensure_ascii=False,indent=2),encoding='utf-8')
                self.activity.set('报告已导出'+('（IP 已隐藏）' if self.export_hide.get() else '（含 IP）'))
            except OSError:
                messagebox.showerror('导出失败','无法写入所选位置，请选择可写文件夹。',parent=self.root)

    def help(self):
        os.startfile(str(HERE/'使用说明.txt'))

    def close(self):
        self.stop_event.set()
        self.root.destroy()


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root',type=Path,default=checks.ROOT,help='本机实际已部署的保护目录')
    parser.add_argument('--scan',action='store_true',help='只读检测并输出隐藏 IP 的 JSON，不打开界面')
    parser.add_argument('--admin-review',action='store_true',help='管理员只读核验模式；仍不修改保护规则')
    args=parser.parse_args()
    guard_root=args.root.expanduser().absolute()
    if args.admin_review and not wfp_audit.elevated():
        raise SystemExit('administrator_review_permission_not_granted')
    if args.scan:
        live=monitor.LiveMonitor(guard_root)
        live.inventory()
        live.auxiliary()
        print(json.dumps(checks.export_report(live.snapshot()),ensure_ascii=False,indent=2))
        return
    if sys.platform=='win32':
        import ctypes
        try:ctypes.windll.shcore.SetProcessDpiAwareness(1)
        except Exception:pass
    root=tk.Tk()
    DetectorApp(root,guard_root=guard_root)
    root.mainloop()


if __name__=='__main__':
    main()
