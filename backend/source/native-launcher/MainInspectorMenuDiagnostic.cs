// Read-only diagnosis of fixed developer-menu targets in a pinned Claude main.
// No activation, keystrokes, invocation, preference change, socket or app code.
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Windows.Automation;

internal static partial class DevToolsUi {
    [DllImport("user32.dll")] static extern IntPtr WindowFromPoint(InspectorPoint point);

    static string MenuDiagnosticToken(string value) {
        if(String.IsNullOrEmpty(value))return "";
        if(value.Length>80)return "unrecognized";
        foreach(char c in value)
            if(!Char.IsLetterOrDigit(c) && c!='_' && c!='-' && c!='.' && c!='#')return "unrecognized";
        return value;
    }

    static object MenuDiagnosticWindow(IntPtr hwnd) {
        bool exists=hwnd!=IntPtr.Zero && IsWindow(hwnd);
        uint owner=0;
        if(exists)GetWindowThreadProcessId(hwnd,out owner);
        IntPtr rootOwner=exists?MainMenuAncestor(hwnd,3):IntPtr.Zero;
        return new {hwnd=hwnd.ToInt64(),exists=exists,visible=exists&&IsWindowVisible(hwnd),
            windowClass=exists?MenuDiagnosticToken(WindowClass(hwnd)):"",ownerPid=owner,
            ownerIsMain=exists&&owner==(uint)Pid,rootOwnerHwnd=rootOwner.ToInt64(),
            rootOwnerIsPinnedMain=exists&&rootOwner==MainInspectorWindow};
    }

    static object MenuDiagnosticNode(AutomationElement item) {
        var current=item.Current;
        return new {frameworkId=MenuDiagnosticToken(current.FrameworkId),
            controlType=current.ControlType.ProgrammaticName,controlTypeId=current.ControlType.Id,
            processId=current.ProcessId,isEnabled=current.IsEnabled,isOffscreen=current.IsOffscreen,
            nativeWindow=MenuDiagnosticWindow(new IntPtr(current.NativeWindowHandle))};
    }

    static bool MenuDiagnosticPattern(AutomationElement item,AutomationPattern pattern) {
        object value;
        return item.TryGetCurrentPattern(pattern,out value);
    }

    static bool PointIsWithinMenuTarget(AutomationElement target,System.Windows.Point point) {
        // Read runtime identity only, never the hit object's/ancestors' names.
        AutomationElement actual=AutomationElement.FromPoint(point);
        for(int i=0;i<7 && actual!=null;i++) {
            if(Automation.Compare(actual,target))return true;
            actual=TreeWalker.ControlViewWalker.GetParent(actual);
        }
        return false;
    }

    static object MenuDiagnosticMsaa(AutomationElement item) {
        try {
            var current=item.Current;
            if(current.IsOffscreen || current.BoundingRectangle.Width<=0 || current.BoundingRectangle.Height<=0)
                return new {available=false,reason="target_not_visible"};
            var point=item.GetClickablePoint(); // A read only; no mouse action.
            var nativePoint=new InspectorPoint {X=(int)Math.Round(point.X),Y=(int)Math.Round(point.Y)};
            IntPtr pointWindow=WindowFromPoint(nativePoint);uint pointOwner;
            if(pointWindow==IntPtr.Zero)return new {available=false,reason="point_window_unavailable"};
            GetWindowThreadProcessId(pointWindow,out pointOwner);
            if(pointOwner!=(uint)Pid)return new {available=false,reason="point_not_owned"};
            if(!PointIsWithinMenuTarget(item,point))
                return new {available=false,reason="point_not_target"};
            using(var native=new NativeMenuAccessible()) {
                int hr=AccessibleObjectFromPoint(nativePoint,out native.Accessible,out native.Child);
                if(hr!=0 || native.Accessible==null || !(native.Child is int))
                    return new {available=false,reason="msaa_unavailable"};
                IntPtr hwnd;uint owner;
                if(WindowFromAccessibleObject(native.Accessible,out hwnd)!=0 || hwnd==IntPtr.Zero || !IsWindow(hwnd))
                    return new {available=false,reason="msaa_window_unavailable"};
                GetWindowThreadProcessId(hwnd,out owner);
                if(owner!=(uint)Pid)return new {available=false,reason="msaa_not_owned"};
                // No get_accName/value/description here. Only state/role of the
                // confirmed exact UIA target's hit object is read and returned.
                object role=native.Accessible.get_accRole(native.Child);
                object state=native.Accessible.get_accState(native.Child);
                if(!(role is int) || !(state is int))
                    return new {available=false,reason="msaa_non_numeric"};
                int flags=(int)state;
                return new {available=true,reason="read_only_target_hit",scopeConfirmed=true,
                    childId=(int)native.Child,role=(int)role,rawState=flags,
                    checkedFlag=(flags&0x10)!=0,mixedFlag=(flags&0x20)!=0,
                    unavailableFlag=(flags&1)!=0,invisibleFlag=(flags&0x8000)!=0,
                    offscreenFlag=(flags&0x10000)!=0,accessibleWindow=MenuDiagnosticWindow(hwnd)};
            }
        }catch {return new {available=false,reason="provider_unavailable"};}
    }

    static object MainInspectorMenuDiagnostic() {
        // No Foreground/NoModal/Activate. Root opens the menu beforehand with
        // ordinary UI; this command must not disturb even a closed/covered menu.
        Alive();MainInspectorWindow=FindMainInspectorWindow();
        var main=MainInspectorRoot();
        Condition names=new OrCondition(
            new PropertyCondition(AutomationElement.NameProperty,"开发者"),
            new PropertyCondition(AutomationElement.NameProperty,"Developer"),
            new PropertyCondition(AutomationElement.NameProperty,"Enable Main Process Debugger"),
            new PropertyCondition(AutomationElement.NameProperty,"Menu"));
        var matches=main.FindAll(TreeScope.Descendants,names);
        if(matches.Count>16)throw new BridgeFailure("MainMenuDiagnosticTargetsAmbiguous");
        var targets=new List<object>();
        foreach(AutomationElement item in matches) {
            string name=item.Current.Name;
            string kind=name=="开发者"?"developer_zh":name=="Developer"?"developer_en":
                name=="Enable Main Process Debugger"?"main_debugger_toggle":name=="Menu"?"local_shell_menu":null;
            if(kind==null)continue;
            object toggle;string toggleState="unavailable";
            bool hasToggle=item.TryGetCurrentPattern(TogglePattern.Pattern,out toggle);
            if(hasToggle) {
                var state=((TogglePattern)toggle).Current.ToggleState;
                toggleState=state==ToggleState.On?"on":state==ToggleState.Off?"off":"indeterminate";
            }
            var ancestors=new List<object>();
            AutomationElement ancestor=item;
            for(int i=0;i<9 && ancestor!=null;i++) {
                ancestors.Add(MenuDiagnosticNode(ancestor));
                if(Automation.Compare(ancestor,main))break;
                ancestor=TreeWalker.ControlViewWalker.GetParent(ancestor);
            }
            targets.Add(new {target=kind,node=MenuDiagnosticNode(item),
                patterns=new {toggle=hasToggle,
                    invoke=MenuDiagnosticPattern(item,InvokePattern.Pattern),
                    expandCollapse=MenuDiagnosticPattern(item,ExpandCollapsePattern.Pattern),
                    value=MenuDiagnosticPattern(item,ValuePattern.Pattern),
                    selectionItem=MenuDiagnosticPattern(item,SelectionItemPattern.Pattern)},
                toggleState=toggleState,msaa=MenuDiagnosticMsaa(item),ancestors=ancestors.ToArray(),
                scopeRejection=kind=="local_shell_menu"?LocalShellMenuRejection(item):NativeMainMenuRejection(item)});
        }
        Alive();CheckWindow(MainInspectorWindow,false);
        return new {readOnly=true,inputPerformed=false,mainPid=Pid,
            mainCreation=((ulong)ProcessCreated).ToString("x16"),
            mainWindow=MenuDiagnosticWindow(MainInspectorWindow),targetCount=targets.Count,
            targets=targets.ToArray()};
    }
}
