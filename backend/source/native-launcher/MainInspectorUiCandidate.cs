// UNINSTALLED CANDIDATE. Only the official Claude native developer menu is used.
// No CLI inspect flag, vendor-signature bypass, debug socket client or app patch.
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Threading;
using System.Windows.Automation;
using Accessibility;

internal static partial class DevToolsUi {
    static IntPtr MainInspectorWindow;
    static string MainInspectorStateMechanism;
    static readonly List<object> MainInspectorMenuAttempts=new List<object>();
    [DllImport("user32.dll",EntryPoint="GetAncestor")] static extern IntPtr MainMenuAncestor(IntPtr hwnd,uint flags);

    static bool NativeMenuHostShape(string framework,int type,string windowClass,
        bool sameProcess,bool rootOwnerIsMain,bool isMainWindow) {
        return framework=="Win32" && type==ControlType.Pane.Id &&
            windowClass=="Chrome_WidgetWin_1" && sameProcess && rootOwnerIsMain && !isMainWindow;
    }

    static bool IsNativeMainMenuHost(IntPtr hwnd) {
        if(hwnd==IntPtr.Zero || !IsWindow(hwnd))return false;
        uint owner;GetWindowThreadProcessId(hwnd,out owner);
        return hwnd!=MainInspectorWindow && owner==(uint)Pid &&
            WindowClass(hwnd)=="Chrome_WidgetWin_1" &&
            MainMenuAncestor(hwnd,3)==MainInspectorWindow;
    }

    [StructLayout(LayoutKind.Sequential)] struct InspectorPoint {public int X,Y;}
    [DllImport("oleacc.dll")] static extern int AccessibleObjectFromPoint(
        InspectorPoint point,[MarshalAs(UnmanagedType.Interface)] out IAccessible accessible,
        [MarshalAs(UnmanagedType.Struct)] out object child);
    [DllImport("oleacc.dll")] static extern int WindowFromAccessibleObject(
        [MarshalAs(UnmanagedType.Interface)] IAccessible accessible,out IntPtr hwnd);
    sealed class NativeMenuAccessible : IDisposable {
        internal IAccessible Accessible;
        internal object Child;
        internal int State,Role;
        public void Dispose() {
            if(Accessible!=null && Marshal.IsComObject(Accessible))Marshal.ReleaseComObject(Accessible);
            Accessible=null;
        }
    }

    static NativeMenuAccessible MainNativeAccessible(AutomationElement item) {
        Foreground(MainInspectorWindow);
        if(item==null || !WithinNativeMainMenu(item) || item.Current.IsOffscreen || !item.Current.IsEnabled)
            throw new BridgeFailure("NativeMenuItemChanged");
        string name=item.Current.Name;
        if(name!="开发者" && name!="Developer" && name!="Enable Main Process Debugger")
            throw new BridgeFailure("NativeMenuItemUnexpected");
        var point=item.GetClickablePoint();
        var native=new NativeMenuAccessible();
        try {
            int hr=AccessibleObjectFromPoint(new InspectorPoint {
                X=(int)Math.Round(point.X),Y=(int)Math.Round(point.Y)},out native.Accessible,out native.Child);
            if(hr!=0 || native.Accessible==null || !(native.Child is int) || (int)native.Child<0)
                throw new BridgeFailure("NativeMenuMsaaUnavailable");
            IntPtr hwnd;uint owner;
            if(WindowFromAccessibleObject(native.Accessible,out hwnd)!=0 || hwnd==IntPtr.Zero || !IsWindow(hwnd))
                throw new BridgeFailure("NativeMenuMsaaWindowUnavailable");
            GetWindowThreadProcessId(hwnd,out owner);
            if(owner!=Pid || (hwnd!=MainInspectorWindow && !IsNativeMainMenuHost(hwnd)))
                throw new BridgeFailure("NativeMenuMsaaOwnerMismatch");
            if(native.Accessible.get_accName(native.Child)!=name)
                throw new BridgeFailure("NativeMenuMsaaItemMismatch");
            object role=native.Accessible.get_accRole(native.Child),state=native.Accessible.get_accState(native.Child);
            if(!(role is int) || !(state is int))throw new BridgeFailure("NativeMenuMsaaStateUnknown");
            native.Role=(int)role;native.State=(int)state;
            if(native.Role!=12 && native.Role!=44)throw new BridgeFailure("NativeMenuMsaaRoleUnknown");
            if((native.State&0x18821)!=0)throw new BridgeFailure("NativeMenuMsaaStateUnknown");
            return native;
        }catch {native.Dispose();throw;}
    }

    static IntPtr FindMainInspectorWindow() {
        IntPtr found=IntPtr.Zero;
        foreach(IntPtr item in OwnedWindows()) {
            if(Title(item)!="Claude" || !IsOwnChromeWindow(item) ||
                !IsWindowVisible(item))continue;
            if(found!=IntPtr.Zero)throw new BridgeFailure("MainWindowAmbiguous");
            found=item;
        }
        if(found==IntPtr.Zero)throw new BridgeFailure("MainWindowUnavailable");
        CheckWindow(found,false);
        return found;
    }

    static bool CaptureMainInspectorForeground() {
        // Win32 identity only, before READY/GO. No menu/UI access or activation.
        MainInspectorWindow=FindMainInspectorWindow();
        return IsWindowVisible(MainInspectorWindow) && IsWindowEnabled(MainInspectorWindow) &&
            !IsIconic(MainInspectorWindow) && GetForegroundWindow()==MainInspectorWindow;
    }

    static void ValidateMainInspectorForeground() {
        if(MainInspectorWindow==IntPtr.Zero || FindMainInspectorWindow()!=MainInspectorWindow)
            throw new BridgeFailure("AlreadyForegroundMainChanged");
        CheckWindow(MainInspectorWindow,false);NoModal();
        if(!IsWindowVisible(MainInspectorWindow) || !IsWindowEnabled(MainInspectorWindow) ||
            IsIconic(MainInspectorWindow) || GetForegroundWindow()!=MainInspectorWindow)
            throw new BridgeFailure("AlreadyForegroundMainChanged");
    }

    static AutomationElement MainInspectorRoot() {
        if(MainInspectorWindow==IntPtr.Zero || FindMainInspectorWindow()!=MainInspectorWindow)
            throw new BridgeFailure("PinnedMainWindowChanged");
        CheckWindow(MainInspectorWindow,false);
        return AutomationElement.FromHandle(MainInspectorWindow);
    }

    static string NativeMainMenuRejection(AutomationElement item) {
        // Actual signed app: CheckBox/MenuItem -> Chrome Menu -> Chrome
        // MenuBar -> Win32 native popup Pane -> exact pinned main Window.
        // A DOM menu cannot qualify via PID alone: Document is rejected, the
        // MenuBar must precede the native HWND, and RootOwner must be main.
        if(item.Current.ProcessId!=Pid)return "foreign_process";
        AutomationElement ancestor=item;
        bool menuBar=false,host=false;
        for(int i=0;i<10 && ancestor!=null;i++) {
            var current=ancestor.Current;
            if(current.ProcessId!=Pid)return "foreign_ancestor";
            if(current.ControlType==ControlType.Document)return "document_ancestor";
            if(current.ControlType==ControlType.MenuBar) {
                if(current.FrameworkId!="Chrome")return "menubar_framework";
                if(menuBar || host)return "menubar_order";
                menuBar=true;
            }
            IntPtr hwnd=new IntPtr(current.NativeWindowHandle);
            if(hwnd==MainInspectorWindow)
                return menuBar && host && current.ControlType==ControlType.Window ? "accepted" : "main_chain_incomplete";
            if(hwnd!=IntPtr.Zero) {
                uint owner;GetWindowThreadProcessId(hwnd,out owner);
                if(!menuBar || host)return "native_host_order";
                if(!NativeMenuHostShape(current.FrameworkId,current.ControlType.Id,
                    WindowClass(hwnd),owner==(uint)Pid,MainMenuAncestor(hwnd,3)==MainInspectorWindow,
                    hwnd==MainInspectorWindow) || !IsNativeMainMenuHost(hwnd))return "native_host_identity";
                host=true;
            }
            ancestor=TreeWalker.ControlViewWalker.GetParent(ancestor);
        }
        return ancestor==null ? "missing_main_ancestor" : "ancestor_depth_limit";
    }

    static bool WithinNativeMainMenu(AutomationElement item) {
        return NativeMainMenuRejection(item)=="accepted";
    }

    static bool ExactLocalShellUri(string value,string expected) {
        if(String.IsNullOrEmpty(value) || String.IsNullOrEmpty(expected))return false;
        try {
            Uri uri;
            return Uri.TryCreate(value,UriKind.Absolute,out uri) && uri.IsFile && !uri.IsUnc &&
                String.IsNullOrEmpty(uri.Host) && String.IsNullOrEmpty(uri.UserInfo) &&
                String.IsNullOrEmpty(uri.Query) && String.IsNullOrEmpty(uri.Fragment) &&
                String.Equals(System.IO.Path.GetFullPath(uri.LocalPath),
                    System.IO.Path.GetFullPath(expected),StringComparison.OrdinalIgnoreCase);
        }catch{return false;}
    }

    static string LocalShellMenuRejection(AutomationElement item) {
        if(item==null)return "missing_button";
        var value=item.Current;
        if(value.ProcessId!=Pid)return "foreign_process";
        if(value.ControlType!=ControlType.Button || value.Name!="Menu")return "wrong_button";
        if(value.IsOffscreen || !value.IsEnabled)return "button_unavailable";
        if(value.BoundingRectangle.Width<=0 || value.BoundingRectangle.Height<=0)return "empty_rectangle";
        bool document=false;AutomationElement ancestor=item;
        for(int i=0;i<16 && ancestor!=null;i++) {
            var current=ancestor.Current;
            if(current.ProcessId!=Pid)return "foreign_ancestor";
            if(current.ControlType==ControlType.Document) {
                if(document)return "multiple_documents";
                object pattern;
                if(!ancestor.TryGetCurrentPattern(ValuePattern.Pattern,out pattern))return "document_value_unavailable";
                if(!ExactLocalShellUri(((ValuePattern)pattern).Current.Value,ExpectedLocalFrontend))return "document_uri_mismatch";
                document=true;
            }
            IntPtr hwnd=new IntPtr(current.NativeWindowHandle);
            if(hwnd==MainInspectorWindow)
                return document && current.ControlType==ControlType.Window ? "accepted" : "local_shell_chain_incomplete";
            if(hwnd!=IntPtr.Zero) {
                uint owner;GetWindowThreadProcessId(hwnd,out owner);
                if(owner!=(uint)Pid || MainMenuAncestor(hwnd,3)!=MainInspectorWindow)return "foreign_native_ancestor";
            }
            ancestor=TreeWalker.ControlViewWalker.GetParent(ancestor);
        }
        return "local_shell_depth_or_main_missing";
    }

    static AutomationElement LocalShellMenuButton(int waitMs) {
        long until=Clock.ElapsedMilliseconds+waitMs;
        do {
            Foreground(MainInspectorWindow);
            var matches=MainInspectorRoot().FindAll(TreeScope.Descendants,new AndCondition(
                new PropertyCondition(AutomationElement.ControlTypeProperty,ControlType.Button),
                new PropertyCondition(AutomationElement.NameProperty,"Menu")));
            if(matches.Count>16)throw new BridgeFailure("LocalShellMenuAmbiguous");
            AutomationElement found=null;int accepted=0;
            var rejected=new Dictionary<string,int>();
            foreach(AutomationElement item in matches) {
                string reason=LocalShellMenuRejection(item);
                if(reason=="accepted"){found=item;accepted++;}
                else {int old;rejected.TryGetValue(reason,out old);rejected[reason]=old+1;}
            }
            if(accepted>1 || accepted==1 || Clock.ElapsedMilliseconds>=until) {
                RecordMainMenuAttempt("local_shell_menu",matches.Count,0,0,0,0,rejected,accepted);
                if(accepted>1)throw new BridgeFailure("LocalShellMenuAmbiguous");
                if(accepted==1)return found;
                return null;
            }
            Thread.Sleep(100);
        }while(true);
    }

    static void OpenLocalShellMenu() {
        // Observed cold/offline app: Left Alt may not open the native menu, but
        // this fixed button in the signed local frontend does. No remote page
        // button, arbitrary DOM command or coordinate fallback is permitted.
        AutomationElement button=LocalShellMenuButton(1500);
        if(button==null)throw new BridgeFailure("LocalShellMenuUnavailable");
        Foreground(MainInspectorWindow);
        if(LocalShellMenuRejection(button)!="accepted")throw new BridgeFailure("LocalShellMenuChanged");
        AutomationElement current=LocalShellMenuButton(100);
        if(current==null || !Automation.Compare(button,current))throw new BridgeFailure("LocalShellMenuChanged");
        object action;
        if(!button.TryGetCurrentPattern(InvokePattern.Pattern,out action))throw new BridgeFailure("LocalShellMenuInvokeUnavailable");
        Foreground(MainInspectorWindow);
        ((InvokePattern)action).Invoke();
    }

    static void RecordMainMenuAttempt(string target,int matches,int offscreen,int disabled,
        int wrongType,int emptyRectangle,Dictionary<string,int> rejections,int accepted) {
        if(MainInspectorMenuAttempts.Count>=6)MainInspectorMenuAttempts.RemoveAt(0);
        MainInspectorMenuAttempts.Add(new {target=target,matchingNodes=matches,
            offscreenNodes=offscreen,disabledNodes=disabled,wrongTypeNodes=wrongType,
            emptyRectangleNodes=emptyRectangle,ancestorRejections=rejections,acceptedNodes=accepted});
    }

    static AutomationElement MainNativeMenuItem(string first,string second,int waitMs) {
        long until=Clock.ElapsedMilliseconds+waitMs;
        do {
            Foreground(MainInspectorWindow);
            Condition name=String.IsNullOrEmpty(second)
                ? (Condition)new PropertyCondition(AutomationElement.NameProperty,first)
                : new OrCondition(new PropertyCondition(AutomationElement.NameProperty,first),
                                  new PropertyCondition(AutomationElement.NameProperty,second));
            var matches=MainInspectorRoot().FindAll(TreeScope.Descendants,name);
            AutomationElement found=null;int count=0,offscreen=0,disabled=0,wrongType=0,empty=0;
            var rejections=new Dictionary<string,int>();
            foreach(AutomationElement item in matches) {
                var value=item.Current;
                if(value.IsOffscreen){offscreen++;continue;}
                if(!value.IsEnabled){disabled++;continue;}
                if(value.ControlType!=ControlType.MenuItem && value.ControlType!=ControlType.CheckBox){wrongType++;continue;}
                string rejection=NativeMainMenuRejection(item);
                if(rejection!="accepted") {
                    int previous;rejections.TryGetValue(rejection,out previous);rejections[rejection]=previous+1;continue;
                }
                if(value.BoundingRectangle.Width<=0 || value.BoundingRectangle.Height<=0){empty++;continue;}
                found=item;++count;
            }
            if(count>1 || count==1 || Clock.ElapsedMilliseconds>=until) {
                RecordMainMenuAttempt(first=="Enable Main Process Debugger"?"main_debugger_toggle":"developer",
                    matches.Count,offscreen,disabled,wrongType,empty,rejections,count);
                if(count>1)throw new BridgeFailure("NativeMenuItemAmbiguous");
                if(count==1)return found;
                break;
            }
            Thread.Sleep(100);
        }while(true);
        return null;
    }

    static void InvokeMainNativeMenuItem(AutomationElement item) {
        Foreground(MainInspectorWindow);
        if(item==null || !WithinNativeMainMenu(item) || item.Current.IsOffscreen || !item.Current.IsEnabled)
            throw new BridgeFailure("NativeMenuItemChanged");
        object action;
        if(item.TryGetCurrentPattern(ExpandCollapsePattern.Pattern,out action)) {
            var expand=(ExpandCollapsePattern)action;
            if(expand.Current.ExpandCollapseState==ExpandCollapseState.Collapsed) {
                expand.Expand();return;
            }
            if(expand.Current.ExpandCollapseState==ExpandCollapseState.Expanded)return;
        }
        if(item.TryGetCurrentPattern(InvokePattern.Pattern,out action)) {
            ((InvokePattern)action).Invoke();return;
        }
        if(item.TryGetCurrentPattern(TogglePattern.Pattern,out action)) {
            ((TogglePattern)action).Toggle();return;
        }
        using(var native=MainNativeAccessible(item))native.Accessible.accDoDefaultAction(native.Child);
    }

    static int MainInspectorCheckedState(AutomationElement item) {
        if(item==null || !WithinNativeMainMenu(item) || item.Current.Name!="Enable Main Process Debugger" ||
            item.Current.IsOffscreen || !item.Current.IsEnabled)
            throw new BridgeFailure("MainInspectorItemChanged");
        object pattern;
        if(item.TryGetCurrentPattern(TogglePattern.Pattern,out pattern)) {
            ToggleState state=((TogglePattern)pattern).Current.ToggleState;
            if(state==ToggleState.Off) {MainInspectorStateMechanism="uia-toggle";return 0;}
            if(state==ToggleState.On) {MainInspectorStateMechanism="uia-toggle";return 1;}
            throw new BridgeFailure("MainInspectorStateUnknown");
        }
        using(var native=MainNativeAccessible(item)) {
            // Source/observed item is an actual MenuItemCheckBox. MSAA state
            // CHECKED is 0x10, MIXED is 0x20, UNAVAILABLE is 0x1. Absence of a
            // checkbox-capable native pattern is never treated as unchecked.
            MainInspectorStateMechanism="msaa-checkbox";
            return MainInspectorMsaaState(native.Role,native.State);
        }
    }

    static int MainInspectorMsaaState(int role,int state) {
        if((role!=12 && role!=44) || (state&0x18821)!=0)
            throw new BridgeFailure("MainInspectorStateUnknown");
        return (state&0x10)!=0 ? 1 : 0;
    }

    // Pure decision helper for offline tests; unknown is never an invocation.
    static bool MainInspectorShouldInvoke(int state,bool enable) {
        if(state==0 || state==1)return state!=(enable?1:0);
        throw new BridgeFailure("MainInspectorStateUnknown");
    }

    static IntPtr CaptureUniqueInspectorDevTools() {
        IntPtr found=IntPtr.Zero;
        foreach(IntPtr item in OwnedWindows()) {
            if(!IsDevTitle(Title(item)) || !IsOwnChromeWindow(item) ||
                !IsWindowVisible(item) || !IsWindowEnabled(item) || IsIconic(item))continue;
            if(found!=IntPtr.Zero)return IntPtr.Zero;
            found=item;
        }
        return found;
    }

    static string RestoreInspectorDevTools(IntPtr original) {
        // The ALREADY token authorized only the main HWND. It cannot be widened
        // into permission to activate another window, even one owned by Claude.
        if(AlreadyForegroundOnly)return "foreground_scope_main_only";
        if(original==IntPtr.Zero)return "no_unique_prior_devtools";
        long until=Clock.ElapsedMilliseconds+1400;
        do {
            Alive();
            if(CaptureUniqueInspectorDevTools()!=original)return "prior_devtools_changed";
            IntPtr foreground=GetForegroundWindow();
            if(foreground!=MainInspectorWindow && foreground!=original)break;
            Thread.Sleep(100);
        }while(Clock.ElapsedMilliseconds<until);
        Thread.Sleep(180);Alive();
        if(CaptureUniqueInspectorDevTools()!=original)return "prior_devtools_changed";
        try {
            // Existing NoModal and Activate checks remain intact. No browser,
            // third-party window, new inspector or unknown dialog is used.
            NoModal();Dev=original;Activate(original,true);
            return GetForegroundWindow()==original ? "restored" : "restore_unconfirmed";
        }catch(BridgeFailure){return "existing_window_protection_rejected";}
    }

    static object MainInspector(bool enable) {
        Alive();
        if(MainInspectorWindow==IntPtr.Zero || FindMainInspectorWindow()!=MainInspectorWindow)
            throw new BridgeFailure("PinnedMainWindowChanged");
        IntPtr originalDevTools=CaptureUniqueInspectorDevTools();
        if(AlreadyForegroundOnly)ValidateMainInspectorForeground();
        else Activate(MainInspectorWindow,false);
        Foreground(MainInspectorWindow);
        var developer=MainNativeMenuItem("开发者","Developer",100);
        if(developer==null) {
            // Parent observed Left Alt opening the native app menu. This is
            // directed only at the exact pinned main HWND, never DevTools.
            Keys(MainInspectorWindow,false,0x12);
            developer=MainNativeMenuItem("开发者","Developer",2500);
        }
        if(developer==null) {
            OpenLocalShellMenu();
            developer=MainNativeMenuItem("开发者","Developer",2500);
        }
        if(developer==null)throw new BridgeFailure("DeveloperMenuUnavailable");
        InvokeMainNativeMenuItem(developer);
        var toggle=MainNativeMenuItem("Enable Main Process Debugger",null,2500);
        if(toggle==null)throw new BridgeFailure("MainInspectorMenuUnavailable");
        int before=MainInspectorCheckedState(toggle);
        bool invoke=MainInspectorShouldInvoke(before,enable);
        if(!invoke) {
            // Never toggle when already in the requested state. Menu-only Escape
            // leaves the main app and all debugging sessions intact.
            Chord(MainInspectorWindow,27);Chord(MainInspectorWindow,27);
            string restore=RestoreInspectorDevTools(originalDevTools);
            return new {source="official_developer_menu",stateBefore=before==1?"on":"off",invoked=false,
                alreadyEnabled=before==1,targetEnabled=enable,toggleRequested=false,menuStateConfirmed=true,
                stateMechanism=MainInspectorStateMechanism,mainHwnd=MainInspectorWindow.ToInt64(),
                portOwnershipVerified=false,devToolsRestored=restore=="restored",devToolsRestoreReason=restore};
        }
        // Recheck immediately before the one and only requested toggle action.
        if(MainInspectorCheckedState(toggle)!=before)throw new BridgeFailure("MainInspectorStateChanged");
        if(enable && before==0)PrepareInspectorNoticeOpenInvocation();
        InvokeMainNativeMenuItem(toggle);
        Alive();
        string inspectorNotice=AcknowledgeInvokedInspectorNotice(enable,true,before);
        // Opening this official entry can focus Chrome's inspector UI. Do not
        // send keys/clicks to Chrome or dismiss an unexpected dialog afterwards.
        // The caller MUST verify loopback listener ownership and process identity
        // before installing policy, and close the Node inspector immediately.
        string restored=RestoreInspectorDevTools(originalDevTools);
        return new {source="official_developer_menu",stateBefore=before==1?"on":"off",invoked=true,
            alreadyEnabled=before==1,targetEnabled=enable,toggleRequested=true,menuStateConfirmed=true,
            stateMechanism=MainInspectorStateMechanism,mainHwnd=MainInspectorWindow.ToInt64(),
            portOwnershipVerified=false,devToolsRestored=restored=="restored",devToolsRestoreReason=restored,
            inspectorNotice=inspectorNotice};
    }
}

internal static partial class DevToolsUi {
    const string InspectorNoticeText = "Inspector session is active. Please open Chrome DevTools (chrome://inspect) in a browser of your choice.";
    static object InspectorNoticeDiagnostic;
    static bool InspectorNoticeOpenCaptured;
    static long InspectorNoticeOpenBirth,InspectorNoticeOpenStarted;
    static IntPtr InspectorNoticeOpenMain;
    static HashSet<IntPtr> InspectorNoticeWindowsBefore;
    internal sealed class InspectorNoticeEvidence {
        internal int ProcessId, ExpectedProcessId, MatchingDialogs, MessageMatches, ActionButtons, ForbiddenNodes, UnknownClientNodes;
        internal long Dialog, Main, RootOwner, NativeOwner;
        internal string WindowClass, Framework, Name, Message, MessageId, ButtonName, ButtonId;
        internal bool WindowType, Visible, Enabled, MainPinned, MainDisabled, ForegroundIsDialog;
        internal bool ButtonType, ButtonVisible, ButtonEnabled, ButtonInvoke;
        internal bool OpenInvocationVerified,NoticeAbsentBefore,NoticeNewHandle;
    }
    static string InspectorNoticeRejection(InspectorNoticeEvidence value) {
        if(value==null)return "missing_evidence";
        if(!value.MainPinned || value.ExpectedProcessId<=0 || value.ProcessId!=value.ExpectedProcessId)return "process_identity";
        if(!value.OpenInvocationVerified || !value.NoticeAbsentBefore || !value.NoticeNewHandle)return "open_invocation_context";
        if(value.Dialog==0 || value.Main==0 || value.Dialog==value.Main || value.RootOwner!=value.Dialog || value.NativeOwner!=0)return "native_owner";
        if(value.MatchingDialogs!=1)return "dialog_count";
        if(value.WindowClass!="#32770" || value.Framework!="Win32" || !value.WindowType)return "native_shape";
        if(value.Name!="Inspector" || !value.Visible || !value.Enabled || value.MainDisabled)return "dialog_state";
        if(!value.ForegroundIsDialog)return "foreground_changed";
        if(value.ForbiddenNodes!=0 || value.UnknownClientNodes!=0)return "unexpected_client_controls";
        if(value.MessageMatches!=1 || value.MessageId!="ContentText" || value.Message!=InspectorNoticeText)return "message_mismatch";
        if(value.ActionButtons!=1 || !value.ButtonType || value.ButtonId!="CommandButton_1" || value.ButtonName!="确定")return "button_mismatch";
        if(!value.ButtonVisible || !value.ButtonEnabled || !value.ButtonInvoke)return "button_unavailable";
        return "accepted";
    }
    static bool InspectorNoticeInvocationAllowed(bool enable,bool invoked,int before) {
        return enable && invoked && before==0;
    }
    static void PrepareInspectorNoticeOpenInvocation() {
        Alive();
        if(Command!="main-inspector" || MainInspectorWindow==IntPtr.Zero || FindMainInspectorWindow()!=MainInspectorWindow)
            throw new BridgeFailure("InspectorNoticeOpenContextInvalid");
        var windows=OwnedWindows();
        if(windows.Count>256)throw new BridgeFailure("InspectorNoticeWindowSetTooLarge");
        var previous=new HashSet<IntPtr>();
        foreach(IntPtr window in windows) {
            // Even an invisible pre-existing Inspector cannot be adopted.
            if(Title(window)=="Inspector")throw new BridgeFailure("PreexistingInspectorNotice");
            previous.Add(window);
        }
        InspectorNoticeWindowsBefore=previous;
        InspectorNoticeOpenBirth=ProcessCreated;
        InspectorNoticeOpenMain=MainInspectorWindow;
        InspectorNoticeOpenStarted=Clock.ElapsedMilliseconds;
        InspectorNoticeOpenCaptured=true;
    }
    static bool InspectorNoticeOpenTimingAllowed(long now,long started) {
        return started>=0 && now>=started && now-started<=2500;
    }
    static bool InspectorNoticeOpenContextCurrent() {
        return InspectorNoticeOpenCaptured && Command=="main-inspector" &&
            InspectorNoticeOpenBirth==ProcessCreated && InspectorNoticeOpenMain==MainInspectorWindow &&
            InspectorNoticeWindowsBefore!=null && InspectorNoticeOpenTimingAllowed(Clock.ElapsedMilliseconds,InspectorNoticeOpenStarted);
    }
    static bool InspectorNoticeNonClientNode(AutomationElement element,AutomationElement dialog) {
        AutomationElement item=element;bool titleBar=false;
        for(int i=0;i<10 && item!=null;i++) {
            var state=item.Current;
            if(state.ProcessId!=Pid)throw new BridgeFailure("InspectorNoticeForeignElement");
            if(state.ControlType==ControlType.Document || state.ControlType==ControlType.Edit || state.ControlType==ControlType.Hyperlink)
                return false;
            if(Automation.Compare(item,dialog))return titleBar;
            if(state.ControlType==ControlType.TitleBar)titleBar=true;
            item=TreeWalker.ControlViewWalker.GetParent(item);
        }
        throw new BridgeFailure("InspectorNoticeElementScopeUnknown");
    }
    static void InspectorNoticeOtherWindows(IntPtr notice) {
        foreach(IntPtr item in OwnedWindows()) {
            if(item==notice || !IsWindowVisible(item) || item==Dev)continue;
            if(IsAuxiliaryDevTools(item) || IsPendingDevTools(item))continue;
            string title=Title(item);
            if(WindowClass(item)=="#32770" || (title.Length!=0 && title!="Claude" && !IsDevTitle(title)))
                throw new BridgeFailure("InspectorNoticeOtherVisibleDialog");
        }
    }
    static InspectorNoticeEvidence InspectorNoticeSnapshot(IntPtr window,int count,out AutomationElement button) {
        Alive();button=null;
        if(MainInspectorWindow==IntPtr.Zero || FindMainInspectorWindow()!=MainInspectorWindow)
            throw new BridgeFailure("PinnedMainWindowChanged");
        uint owner;GetWindowThreadProcessId(window,out owner);
        var value=new InspectorNoticeEvidence {
            ProcessId=(int)owner,ExpectedProcessId=Pid,MatchingDialogs=count,
            Dialog=window.ToInt64(),Main=MainInspectorWindow.ToInt64(),
            RootOwner=MainMenuAncestor(window,3).ToInt64(),NativeOwner=GetWindow(window,4).ToInt64(),
            OpenInvocationVerified=InspectorNoticeOpenContextCurrent(),NoticeAbsentBefore=InspectorNoticeWindowsBefore!=null,
            NoticeNewHandle=InspectorNoticeWindowsBefore!=null && !InspectorNoticeWindowsBefore.Contains(window),
            WindowClass=WindowClass(window),Name=Title(window),
            Visible=IsWindowVisible(window),Enabled=IsWindowEnabled(window),
            MainPinned=true,MainDisabled=!IsWindowEnabled(MainInspectorWindow),
            ForegroundIsDialog=GetForegroundWindow()==window
        };
        InspectorNoticeDiagnostic=new {
            stage="native_identity",classKind=value.WindowClass=="#32770"?"task_dialog":"other",
            sameProcess=owner==(uint)Pid,rootOwnerIsMain=value.RootOwner==value.Main,
            rootOwnerIsSelf=value.RootOwner==value.Dialog,nativeOwnerIsNone=value.NativeOwner==0,
            openInvocationVerified=value.OpenInvocationVerified,newHandle=value.NoticeNewHandle,mainDisabled=value.MainDisabled,
            foregroundIsNotice=value.ForegroundIsDialog,matchingDialogs=count
        };
        // Native facts reject before reading a UIA tree. No same-PID DOM or
        // unrelated native popup is promoted to an input target.
        if(owner!=(uint)Pid || window==MainInspectorWindow || !InspectorNoticeOpenContextCurrent() ||
            InspectorNoticeWindowsBefore.Contains(window) || GetWindow(window,4)!=IntPtr.Zero ||
            MainMenuAncestor(window,3)!=window || WindowClass(window)!="#32770" || Title(window)!="Inspector")
            throw new BridgeFailure("InspectorNoticeNativeIdentityMismatch");
        InspectorNoticeOtherWindows(window);
        AutomationElement root=AutomationElement.FromHandle(window);
        var top=root.Current;
        value.Framework=top.FrameworkId;
        value.WindowType=top.ControlType==ControlType.Window;
        if(top.ProcessId!=Pid || top.NativeWindowHandle!=window.ToInt64() || top.Name!="Inspector")
            throw new BridgeFailure("InspectorNoticeRootMismatch");
        var nodes=root.FindAll(TreeScope.Descendants,Condition.TrueCondition);
        if(nodes.Count>64)throw new BridgeFailure("InspectorNoticeTreeTooLarge");
        foreach(AutomationElement item in nodes) {
            var state=item.Current;
            if(state.ProcessId!=Pid)throw new BridgeFailure("InspectorNoticeForeignElement");
            if(InspectorNoticeNonClientNode(item,root))continue;
            if(state.ControlType==ControlType.Document || state.ControlType==ControlType.Edit ||
                state.ControlType==ControlType.Hyperlink || state.ControlType==ControlType.ComboBox ||
                state.ControlType==ControlType.CheckBox || state.ControlType==ControlType.RadioButton) {
                value.ForbiddenNodes++;continue;
            }
            if(state.ControlType==ControlType.Text && state.AutomationId=="ContentText") {
                value.MessageMatches++;value.Message=state.Name;value.MessageId=state.AutomationId;
                if(state.IsOffscreen || !state.IsEnabled)value.UnknownClientNodes++;
                continue;
            }
            if(state.ControlType==ControlType.Button) {
                value.ActionButtons++;button=item;
                value.ButtonType=true;value.ButtonName=state.Name;value.ButtonId=state.AutomationId;
                value.ButtonVisible=!state.IsOffscreen;value.ButtonEnabled=state.IsEnabled;
                object action;value.ButtonInvoke=item.TryGetCurrentPattern(InvokePattern.Pattern,out action);
                continue;
            }
            value.UnknownClientNodes++;
        }
        InspectorNoticeDiagnostic=new {
            stage="complete_shape",classKind="task_dialog",frameworkKind=value.Framework=="Win32"?"win32":"other",
            rootOwnerIsMain=value.RootOwner==value.Main,rootOwnerIsSelf=value.RootOwner==value.Dialog,
            nativeOwnerIsNone=value.NativeOwner==0,openInvocationVerified=value.OpenInvocationVerified,newHandle=value.NoticeNewHandle,
            messageExact=value.Message==InspectorNoticeText,messageIdExact=value.MessageId=="ContentText",
            matchingMessages=value.MessageMatches,actionButtons=value.ActionButtons,
            buttonExact=value.ButtonName=="确定" && value.ButtonId=="CommandButton_1",
            forbiddenNodes=value.ForbiddenNodes,unknownClientNodes=value.UnknownClientNodes,
            foregroundIsNotice=value.ForegroundIsDialog,rejection=InspectorNoticeRejection(value)
        };
        return value;
    }
    static IntPtr FindExpectedInspectorNotice(out int count) {
        IntPtr found=IntPtr.Zero;count=0;
        foreach(IntPtr item in OwnedWindows()) {
            if(IsWindowVisible(item) && Title(item)=="Inspector") {count++;found=item;}
        }
        return found;
    }
    static string AcknowledgeInvokedInspectorNotice(bool enable,bool invoked,int before) {
        if(!InspectorNoticeInvocationAllowed(enable,invoked,before))return "not_this_open_invocation";
        if(!InspectorNoticeOpenContextCurrent())throw new BridgeFailure("InspectorNoticeOpenContextInvalid");
        long until=InspectorNoticeOpenStarted+2500;
        do {
            Alive();int count;IntPtr notice=FindExpectedInspectorNotice(out count);
            if(count!=0) {
                AutomationElement firstButton;
                var first=InspectorNoticeSnapshot(notice,count,out firstButton);
                string rejected=InspectorNoticeRejection(first);
                if(rejected!="accepted")throw new BridgeFailure("InspectorNoticeRejected:"+rejected);
                // Reobserve the exact same HWND and UIA button immediately before
                // the one Invoke. No activation, coordinates or key fallback.
                int secondCount;IntPtr current=FindExpectedInspectorNotice(out secondCount);
                if(current!=notice)throw new BridgeFailure("InspectorNoticeChanged");
                AutomationElement secondButton;
                var second=InspectorNoticeSnapshot(current,secondCount,out secondButton);
                if(InspectorNoticeRejection(second)!="accepted" || firstButton==null || secondButton==null ||
                    !Automation.Compare(firstButton,secondButton))throw new BridgeFailure("InspectorNoticeChanged");
                object action;
                if(!secondButton.TryGetCurrentPattern(InvokePattern.Pattern,out action))
                    throw new BridgeFailure("InspectorNoticeInvokeUnavailable");
                Alive();
                if(!InspectorNoticeOpenContextCurrent())throw new BridgeFailure("InspectorNoticeOpenContextExpired");
                if(GetForegroundWindow()!=notice)throw new BridgeFailure("UserChangedForeground");
                ((InvokePattern)action).Invoke();
                InspectorNoticeOpenCaptured=false; // Consume this one invocation.
                long vanishedBy=Clock.ElapsedMilliseconds+1500;
                while(IsWindow(notice) && IsWindowVisible(notice) && Clock.ElapsedMilliseconds<vanishedBy) {
                    Alive();Thread.Sleep(50);
                }
                Alive();
                if(IsWindow(notice) && IsWindowVisible(notice))throw new BridgeFailure("InspectorNoticeDismissUnconfirmed");
                NoModal();
                return "exact_observed_native_notice_acknowledged";
            }
            // Still reject other unexpected dialogs. This is a local call to the
            // unchanged common guard, never an exclusion inside NoModal().
            NoModal();
            Thread.Sleep(50);
        }while(Clock.ElapsedMilliseconds<until);
        InspectorNoticeOpenCaptured=false;
        return "not_observed_within_bound";
    }
}
