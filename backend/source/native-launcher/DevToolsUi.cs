// Local, scoped bridge for the user's Claude desktop launcher.
// No browser profile/authentication access, package modification or debug port.
// Only the inspected page's fixed environment metadata expression is executed.
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Net;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Web.Script.Serialization;
using System.Windows.Automation;

internal sealed class BridgeFailure : Exception {
    internal BridgeFailure(string code) : base(code) { }
}

internal static partial class DevToolsUi {
    const uint QueryLimited = 0x1000;
    const uint StillActive = 259;
    static int Pid;
    static string Command;
    static IntPtr ProcessHandle;
    static long ProcessCreated;
    static IntPtr Dev;
    static IntPtr ForegroundReadyDev;
    static bool AlreadyForegroundOnly;
    static int Finished;
    static bool ProbeMarkerFound;
    static int ProbeNodesVisited;
    static string ExpectedLocalFrontend;
    static object ModalDiagnostic;
    static object LiveArmDiagnostic;
    static object JavaScriptStateDiagnostic;
    static string PreferencesCloseMethod;
    static object ActivationDiagnostic;
    static string PreferencesPaneLocator;
    static Timer Deadline;
    static readonly JavaScriptSerializer Json = new JavaScriptSerializer();
    static readonly Stopwatch Clock = Stopwatch.StartNew();
    static readonly HashSet<string> Commands = new HashSet<string>(new string[] {
        "inspect", "configure", "verify", "disable-js", "enable-js", "reload", "hide", "show",
        "arm-monitor", "poll-monitor", "network-check", "park-monitor", "park-monitor-bottom",
        "arm-live", "poll-live", "recover-minimized-monitor", "inspect-js-state", "main-inspector", "main-inspector-close", "inspect-main-inspector-menu"
    });

    [StructLayout(LayoutKind.Sequential)] struct FileTime { public uint Low; public uint High; }
    [StructLayout(LayoutKind.Sequential)] struct KeyboardInput {
        public ushort Vk, Scan; public uint Flags, Time; public UIntPtr Extra;
    }
    [StructLayout(LayoutKind.Sequential)] struct MouseInput {
        public int X, Y; public uint Data, Flags, Time; public UIntPtr Extra;
    }
    [StructLayout(LayoutKind.Explicit)] struct InputUnion {
        [FieldOffset(0)] public KeyboardInput Keyboard;
        [FieldOffset(0)] public MouseInput Mouse;
    }
    [StructLayout(LayoutKind.Sequential)] struct Input { public uint Type; public InputUnion Value; }
    delegate bool WindowCallback(IntPtr hwnd, IntPtr parameter);
    [DllImport("user32.dll")] static extern bool EnumWindows(WindowCallback callback, IntPtr parameter);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] static extern int GetWindowText(IntPtr hwnd, StringBuilder text, int count);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] static extern int GetClassName(IntPtr hwnd, StringBuilder text, int count);
    [DllImport("user32.dll")] static extern uint GetWindowThreadProcessId(IntPtr hwnd, out uint pid);
    [DllImport("user32.dll")] static extern bool IsWindow(IntPtr hwnd);
    [DllImport("user32.dll")] static extern bool IsWindowVisible(IntPtr hwnd);
    [DllImport("user32.dll")] static extern bool IsWindowEnabled(IntPtr hwnd);
    [DllImport("user32.dll")] static extern IntPtr GetForegroundWindow();
    [DllImport("user32.dll")] static extern IntPtr GetWindow(IntPtr hwnd, uint command);
    [DllImport("user32.dll")] static extern bool SetForegroundWindow(IntPtr hwnd);
    [DllImport("user32.dll")] static extern bool ShowWindow(IntPtr hwnd, int command);
    [DllImport("user32.dll")] static extern bool IsIconic(IntPtr hwnd);
    [DllImport("user32.dll")] static extern IntPtr GetLastActivePopup(IntPtr hwnd);
    [DllImport("user32.dll", EntryPoint="GetWindowLongPtrW")] static extern IntPtr GetWindowLongPtr64(IntPtr hwnd,int index);
    [DllImport("user32.dll", EntryPoint="GetWindowLongW")] static extern int GetWindowLong32(IntPtr hwnd,int index);
    [DllImport("user32.dll", SetLastError = true)] static extern bool SetWindowPos(IntPtr hwnd, IntPtr after, int x, int y, int cx, int cy, uint flags);
    [DllImport("user32.dll", SetLastError = true)] static extern uint SendInput(uint count, Input[] inputs, int size);
    [DllImport("kernel32.dll", SetLastError = true)] static extern IntPtr OpenProcess(uint access, bool inherit, int pid);
    [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr handle);
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool GetExitCodeProcess(IntPtr handle, out uint code);
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool GetProcessTimes(IntPtr handle, out FileTime creation, out FileTime exit, out FileTime kernel, out FileTime user);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] static extern bool QueryFullProcessImageName(IntPtr handle, int flags, StringBuilder path, ref int length);

    static long Stamp(FileTime f) { return ((long)f.High << 32) | f.Low; }
    static string Title(IntPtr hwnd) { var b = new StringBuilder(2048); GetWindowText(hwnd, b, b.Capacity); return b.ToString(); }
    static string WindowClass(IntPtr hwnd) { var b = new StringBuilder(256); GetClassName(hwnd, b, b.Capacity); return b.ToString(); }
    static bool IsDevTitle(string value) {
        return value == "Developer Tools - https://claude.ai" ||
            value.StartsWith("Developer Tools - https://claude.ai/", StringComparison.Ordinal) ||
            value == "Developer Tools - chrome-error://chromewebdata/";
    }
    static bool IsOwnChromeWindow(IntPtr hwnd) {
        uint owner; GetWindowThreadProcessId(hwnd,out owner);
        return owner==Pid && WindowClass(hwnd).StartsWith("Chrome_WidgetWin_",StringComparison.Ordinal);
    }
    static bool IsAuxiliaryDevTools(IntPtr hwnd) {
        const string prefix="Developer Tools - ";
        if(!IsOwnChromeWindow(hwnd) || String.IsNullOrEmpty(ExpectedLocalFrontend)) return false;
        string title=Title(hwnd);
        if(!title.StartsWith(prefix,StringComparison.Ordinal)) return false;
        try {
            Uri url;
            return Uri.TryCreate(title.Substring(prefix.Length),UriKind.Absolute,out url) &&
                url.IsFile && !url.IsUnc && String.IsNullOrEmpty(url.Host) &&
                String.Equals(Path.GetFullPath(url.LocalPath),ExpectedLocalFrontend,StringComparison.OrdinalIgnoreCase);
        } catch { return false; }
    }
    static bool IsPendingDevTools(IntPtr hwnd) {
        if(!IsOwnChromeWindow(hwnd)) return false;
        string title=Title(hwnd);
        return title=="Developer Tools" || title=="Developer Tools -" ||
            title=="Developer Tools - " || title=="Developer Tools - about:blank";
    }
    static string Kind(IntPtr hwnd) {
        string t = Title(hwnd);
        if (t == "Claude") return "main";
        if (IsDevTitle(t)) return t.IndexOf("chrome-error:", StringComparison.Ordinal) >= 0 ? "devtools-error-page" : "devtools-claude";
        if (IsAuxiliaryDevTools(hwnd)) return "devtools-auxiliary-local";
        if (IsPendingDevTools(hwnd)) return "devtools-pending";
        return "other";
    }
    static List<IntPtr> OwnedWindows() {
        Alive();
        var result = new List<IntPtr>();
        EnumWindows(delegate(IntPtr w, IntPtr p) {
            uint owner; GetWindowThreadProcessId(w, out owner);
            if (owner == Pid) result.Add(w);
            return true;
        }, IntPtr.Zero);
        return result;
    }
    static void Alive() {
        if (Clock.ElapsedMilliseconds > 58000) throw new BridgeFailure("CommandDeadline");
        uint code; FileTime creation, exit, kernel, user;
        if (ProcessHandle == IntPtr.Zero || !GetExitCodeProcess(ProcessHandle, out code) || code != StillActive ||
            !GetProcessTimes(ProcessHandle, out creation, out exit, out kernel, out user) || Stamp(creation) != ProcessCreated)
            throw new BridgeFailure("MainProcessChanged");
    }
    static void CheckWindow(IntPtr w, bool devtools) {
        Alive(); uint owner;
        if (!IsWindow(w)) throw new BridgeFailure("WindowClosed");
        GetWindowThreadProcessId(w, out owner);
        if (owner != Pid || (devtools ? !IsDevTitle(Title(w)) : Title(w) != "Claude"))
            throw new BridgeFailure("UnexpectedWindow");
    }
    static void NoModal() {
        int auxiliary=0,pending=0,unknown=0; string category=null;
        foreach (IntPtr w in OwnedWindows()) {
            if (!IsWindowVisible(w) || w == Dev) continue;
            string t = Title(w);
            // Known local shell inspectors and transient blank inspectors are
            // never input targets. Their presence must not be confused with an
            // authentication dialog while the remote inspector is being created.
            if(IsAuxiliaryDevTools(w)) { ++auxiliary; continue; }
            if(IsPendingDevTools(w)) { ++pending; continue; }
            // Invisible IME/provider windows are not work surfaces. Visible unknown
            // windows, authentication dialogs and permission prompts are never used.
            if (WindowClass(w) == "#32770" || (t.Length != 0 && t != "Claude" && !IsDevTitle(t))) {
                ++unknown;
                if(category==null) category=WindowClass(w)=="#32770" ? "nativeDialog" :
                    (t.StartsWith("Developer Tools",StringComparison.Ordinal) ? "unrecognisedDeveloperTools" : "unrecognisedWindow");
            }
        }
        if(unknown!=0) {
            ModalDiagnostic=new {category=category,auxiliaryDevTools=auxiliary,pendingDevTools=pending,unrecognisedWindow=unknown};
            throw new BridgeFailure("UnexpectedVisibleDialog");
        }
    }
    static int HideAuxiliaryDevTools() {
        int count=0;
        foreach(IntPtr w in OwnedWindows()) {
            if(w==Dev || (!IsAuxiliaryDevTools(w) && !IsPendingDevTools(w))) continue;
            Alive();
            if(IsWindowVisible(w)) {
                ShowWindow(w,0);
                if(!IsWindowVisible(w)) ++count;
            }
        }
        return count;
    }
    static void Foreground(IntPtr w) {
        CheckWindow(w, w == Dev); NoModal();
        IntPtr foreground = GetForegroundWindow();
        if (foreground == w) return;
        // A native HTML select popup may be the foreground window temporarily.
        uint owner; GetWindowThreadProcessId(foreground, out owner);
        if (owner == Pid && GetWindow(foreground, 4) == w &&
            WindowClass(foreground) == "Chrome_WidgetWin_0" && Title(foreground).Length == 0) return;
        throw new BridgeFailure("UserChangedForeground");
    }
    static void Activate(IntPtr w, bool devtools) {
        CheckWindow(w, devtools); NoModal();
        object before=ActivationWindowMetadata(w);
        object foregroundBefore=ActivationForegroundMetadata();
        long started=Clock.ElapsedMilliseconds;
        bool previouslyVisible=ShowWindow(w,9);
        bool foregroundReturned=SetForegroundWindow(w);
        long until = Clock.ElapsedMilliseconds + 1800;
        while (Clock.ElapsedMilliseconds < until) {
            if (GetForegroundWindow() == w) return;
            Thread.Sleep(80);
        }
        // Only fixed Win32 state metadata. Never window titles, page content,
        // account names, command lines or input history. No extra activation.
        ActivationDiagnostic=new {activationTarget=devtools?"devtools":"main",
            before=before,after=ActivationWindowMetadata(w),
            foregroundBefore=foregroundBefore,foregroundAfter=ActivationForegroundMetadata(),
            showWindowPreviouslyVisible=previouslyVisible,setForegroundReturned=foregroundReturned,
            elapsedMilliseconds=Clock.ElapsedMilliseconds-started};
        throw new BridgeFailure("CannotActivateExpectedWindow");
    }
    static long WindowStyleBits(IntPtr w,int index) {
        return IntPtr.Size==8?GetWindowLongPtr64(w,index).ToInt64():(long)(uint)GetWindowLong32(w,index);
    }
    static object ActivationWindowMetadata(IntPtr w) {
        bool exists=IsWindow(w);
        IntPtr owner=exists?GetWindow(w,4):IntPtr.Zero;
        IntPtr popup=exists?GetLastActivePopup(w):IntPtr.Zero;
        uint ownerPid=0,popupPid=0;
        if(owner!=IntPtr.Zero)GetWindowThreadProcessId(owner,out ownerPid);
        if(popup!=IntPtr.Zero)GetWindowThreadProcessId(popup,out popupPid);
        long style=exists?WindowStyleBits(w,-16):0;
        long extended=exists?WindowStyleBits(w,-20):0;
        return new {exists=exists,visible=exists&&IsWindowVisible(w),
            minimized=exists&&IsIconic(w),enabled=exists&&IsWindowEnabled(w),
            disabledStyle=(style&0x08000000L)!=0,noActivateStyle=(extended&0x08000000L)!=0,
            topmostStyle=(extended&8L)!=0,ownerPresent=owner!=IntPtr.Zero,
            ownerIsTargetProcess=owner!=IntPtr.Zero&&ownerPid==Pid,
            differentLastPopup=popup!=IntPtr.Zero&&popup!=w,
            lastPopupVisible=popup!=IntPtr.Zero&&popup!=w&&IsWindowVisible(popup),
            lastPopupIsTargetProcess=popup!=IntPtr.Zero&&popup!=w&&popupPid==Pid};
    }
    static object ActivationForegroundMetadata() {
        IntPtr window=GetForegroundWindow();uint foregroundPid=0;
        if(window!=IntPtr.Zero)GetWindowThreadProcessId(window,out foregroundPid);
        return new {present=window!=IntPtr.Zero,pid=foregroundPid,
            isTargetProcess=foregroundPid==(uint)Pid,
            isHelperProcess=foregroundPid==(uint)Process.GetCurrentProcess().Id};
    }
    static Input Key(ushort vk, bool up) {
        return new Input { Type = 1, Value = new InputUnion {
            Keyboard = new KeyboardInput { Vk = vk, Flags = up ? 2u : 0u }
        }};
    }
    static void Keys(IntPtr w, bool checkAfter, params ushort[] keys) {
        Foreground(w);
        var inputs = new List<Input>();
        foreach (ushort k in keys) inputs.Add(Key(k, false));
        for (int i = keys.Length - 1; i >= 0; --i) inputs.Add(Key(keys[i], true));
        if (SendInput((uint)inputs.Count, inputs.ToArray(), Marshal.SizeOf(typeof(Input))) != inputs.Count)
            throw new BridgeFailure("InputNotDelivered");
        Thread.Sleep(130); if (checkAfter) Foreground(w);
    }
    static void Chord(IntPtr w, params ushort[] keys) { Keys(w, true, keys); }
    static AutomationElement Root() { CheckWindow(Dev, true); return AutomationElement.FromHandle(Dev); }
    static AutomationElement Find(Condition condition, string step, int milliseconds) {
        long until = Clock.ElapsedMilliseconds + milliseconds;
        do {
            Foreground(Dev);
            try {
                AutomationElement e = Root().FindFirst(TreeScope.Descendants, condition);
                if (e != null) return e;
            } catch (ElementNotAvailableException) { }
            Thread.Sleep(150);
        } while (Clock.ElapsedMilliseconds < until);
        throw new BridgeFailure("MissingElement:" + step);
    }
    static AutomationElement ById(string id) {
        return Find(new PropertyCondition(AutomationElement.AutomationIdProperty, id), id, 10000);
    }
    static AutomationElement ByName(string name, string step) {
        return Find(new PropertyCondition(AutomationElement.NameProperty, name), step, 10000);
    }
    static void Focus(AutomationElement e) {
        Foreground(Dev); e.SetFocus(); Thread.Sleep(100); Foreground(Dev);
    }
    static void Set(AutomationElement e, string value) {
        Focus(e); object p;
        Foreground(Dev);
        if (e.TryGetCurrentPattern(ValuePattern.Pattern, out p) && !((ValuePattern)p).Current.IsReadOnly)
            ((ValuePattern)p).SetValue(value);
        else if (e.TryGetCurrentPattern(RangeValuePattern.Pattern, out p) && !((RangeValuePattern)p).Current.IsReadOnly) {
            double number;
            if (!Double.TryParse(value, NumberStyles.Float, CultureInfo.InvariantCulture, out number))
                throw new BridgeFailure("NumericFieldValueInvalid");
            ((RangeValuePattern)p).SetValue(number);
        } else throw new BridgeFailure("EditableValuePatternUnavailable");
        Thread.Sleep(120);
    }
    static void SetField(string id, string value) {
        AutomationElement e = Find(new AndCondition(
            new PropertyCondition(AutomationElement.AutomationIdProperty,id),
            new PropertyCondition(AutomationElement.IsEnabledProperty,true)),id+"-enabled",10000);
        Set(e, value); Chord(Dev, 9);
        string confirmed = Value(e);
        if (!String.Equals(confirmed, value, StringComparison.Ordinal)) {
            // The float spinboxes may use equivalent rounded formatting.
            double a, b;
            if (!Double.TryParse(value, NumberStyles.Float, CultureInfo.InvariantCulture, out a) ||
                !Double.TryParse(confirmed, NumberStyles.Float, CultureInfo.InvariantCulture, out b) || Math.Abs(a-b) > 0.0001)
                throw new BridgeFailure("FieldValueNotConfirmed:" + id);
        }
    }
    static void SelectConsole() {
        AutomationElement e = ById("tab-console"); object p;
        Foreground(Dev);
        if (e.TryGetCurrentPattern(SelectionItemPattern.Pattern, out p)) ((SelectionItemPattern)p).Select();
        else if (e.TryGetCurrentPattern(InvokePattern.Pattern, out p)) ((InvokePattern)p).Invoke();
        else { Focus(e); Chord(Dev, 13); }
        Focus(ByName("Console prompt", "console-prompt"));
    }
    static string Value(AutomationElement e) {
        object p; if (e.TryGetCurrentPattern(ValuePattern.Pattern, out p)) return ((ValuePattern)p).Current.Value;
        if (e.TryGetCurrentPattern(RangeValuePattern.Pattern, out p)) return ((RangeValuePattern)p).Current.Value.ToString("R",CultureInfo.InvariantCulture);
        return "";
    }
    static bool MenuCommand(string text, bool optional) {
        Chord(Dev, 0x11, 0x10, 0x50); // Ctrl+Shift+P.
        AutomationElement prompt = ByName("Quick open prompt", "command-menu");
        Set(prompt, ">" + text);
        long until = Clock.ElapsedMilliseconds + 3500;
        while (Clock.ElapsedMilliseconds < until) {
            Foreground(Dev);
            var options = Root().FindAll(TreeScope.Descendants,
                new PropertyCondition(AutomationElement.ControlTypeProperty, ControlType.ListItem));
            foreach (AutomationElement item in options) {
                if (item.Current.IsOffscreen) continue;
                string n = item.Current.Name;
                // Command items append their section, e.g. "Show Sensors Drawer".
                if (n == text || n.StartsWith(text + " ", StringComparison.Ordinal)) {
                    Focus(prompt); Chord(Dev, 13); return true;
                }
                // Enter acts on the first result. Never assume a later match is
                // selected when the first visible result is unrelated.
                break;
            }
            Thread.Sleep(150);
        }
        Chord(Dev, 27);
        if (optional) return false;
        throw new BridgeFailure("CommandNotFound:" + text);
    }
    static AutomationElement VisiblePreferencesPane() {
        // Chromium's HTML id is not always exposed as UIA AutomationId. The
        // one allowed fallback is the actually observed exact accessible name
        // of the Preferences tabpanel, still inside the pinned inspector HWND.
        Foreground(Dev);
        var byId = Root().FindAll(TreeScope.Descendants,
            new PropertyCondition(AutomationElement.AutomationIdProperty, "preferences-tab-content"));
        AutomationElement found = null;
        int visible = 0;
        foreach (AutomationElement item in byId) {
            if (item.Current.IsOffscreen) continue;
            found = item;
            ++visible;
        }
        if (visible > 1) throw new BridgeFailure("PreferencesPaneAmbiguous");
        if (visible == 1) {
            PreferencesPaneLocator = "exact_automation_id";
            return found;
        }
        var byName = Root().FindAll(TreeScope.Descendants,
            new PropertyCondition(AutomationElement.NameProperty, "Preferences panel"));
        foreach (AutomationElement item in byName) {
            if (item.Current.IsOffscreen) continue;
            found = item;
            ++visible;
        }
        if (visible > 1) throw new BridgeFailure("PreferencesPaneAmbiguous");
        if (visible == 1) {
            PreferencesPaneLocator = "exact_accessible_name";
            return found;
        }
        return null;
    }
    static T WaitBoundedAvailability<T>(Func<T> read, Func<long> monotonicMs,
            Action<int> pause, int milliseconds) where T : class {
        // Availability only. A boundary/ambiguity error is never retryable.
        // No command, input, selection, setting or permission is repeated.
        if(read==null || monotonicMs==null || pause==null || milliseconds<1 || milliseconds>3500)
            throw new BridgeFailure("PreferencesWaitInvalid");
        long began=monotonicMs();
        if(began<0 || began>Int64.MaxValue-milliseconds)
            throw new BridgeFailure("PreferencesWaitClockInvalid");
        long until=began+milliseconds;
        while(true) {
            long now=monotonicMs();
            if(now<began)throw new BridgeFailure("PreferencesWaitClockInvalid");
            if(now>until)return null;
            T value=read();
            now=monotonicMs();
            if(now<began)throw new BridgeFailure("PreferencesWaitClockInvalid");
            if(now>until)return null;
            if(value!=null)return value;
            if(now>=until)return null;
            pause((int)Math.Min(100L,until-now));
        }
    }
    static void WaitForPreferencesPane() {
        AutomationElement pane=WaitBoundedAvailability<AutomationElement>(
            delegate { Foreground(Dev); return VisiblePreferencesPane(); },
            delegate { return Clock.ElapsedMilliseconds; },Thread.Sleep,3500);
        if(pane==null)throw new BridgeFailure("PreferencesPaneNotVisible");
    }
    static AutomationElement ExactJavaScriptCheckbox() {
        // This query is scoped to the official Settings > Preferences pane.
        // Do not inspect Command Menu results, page DOM, history or other tabs.
        AutomationElement preferences = VisiblePreferencesPane();
        if (preferences == null) throw new BridgeFailure("PreferencesPaneNotVisible");
        var matches = preferences.FindAll(TreeScope.Descendants, new AndCondition(
            new PropertyCondition(AutomationElement.ControlTypeProperty, ControlType.CheckBox),
            new PropertyCondition(AutomationElement.NameProperty, "Disable JavaScript"),
            new PropertyCondition(AutomationElement.IsEnabledProperty, true)));
        if (matches.Count != 1)
            throw new BridgeFailure("JavaScriptCheckboxMissingOrAmbiguous");
        return matches[0];
    }
    static ToggleState ReadJavaScriptCheckbox() {
        Foreground(Dev);
        AutomationElement checkbox = ExactJavaScriptCheckbox();
        object pattern;
        if (!checkbox.TryGetCurrentPattern(TogglePattern.Pattern, out pattern))
            throw new BridgeFailure("JavaScriptCheckboxToggleUnavailable");
        ToggleState value = ((TogglePattern)pattern).Current.ToggleState;
        if (value != ToggleState.On && value != ToggleState.Off)
            throw new BridgeFailure("JavaScriptCheckboxIndeterminate");
        return value;
    }
    static bool CloseBoundedPreferences<T>(Func<T> readPane, Action<T> closeOnce,
            Func<long> monotonicMs, Action<int> pause, int milliseconds) where T : class {
        if(readPane==null || closeOnce==null || monotonicMs==null || pause==null
                || milliseconds<1 || milliseconds>3500)
            throw new BridgeFailure("PreferencesCloseInvalid");
        long began=monotonicMs();
        if(began<0 || began>Int64.MaxValue-milliseconds)
            throw new BridgeFailure("PreferencesWaitClockInvalid");
        long until=began+milliseconds;
        T pane=readPane();
        long now=monotonicMs();
        if(now<began)throw new BridgeFailure("PreferencesWaitClockInvalid");
        if(now>until)throw new BridgeFailure("JavaScriptPreferencesNotClosed");
        if(pane==null)return false;
        // A single fixed close action. Never repeat it against a new dialog,
        // toggle JavaScript, send Escape blindly, or widen the target scope.
        closeOnce(pane);
        now=monotonicMs();
        if(now<began)throw new BridgeFailure("PreferencesWaitClockInvalid");
        if(now>=until)throw new BridgeFailure("JavaScriptPreferencesNotClosed");
        object marker=new object();
        object closed=WaitBoundedAvailability<object>(
            delegate { return readPane()==null?marker:null; },monotonicMs,pause,(int)(until-now));
        if(closed==null)throw new BridgeFailure("JavaScriptPreferencesNotClosed");
        return true;
    }
    static AutomationElement ExactSettingsDialog(AutomationElement preferences) {
        Foreground(Dev);
        AutomationElement inspector=Root();
        AutomationElement node=preferences;
        for(int depth=0;node!=null && depth<20;++depth) {
            if(Automation.Compare(node,inspector))break;
            // Actual Cua observation: the Settings dialog itself is unnamed;
            // its visible Settings heading, Close button and Preferences panel
            // are siblings/descendants. UIA's dialog ControlType also varies.
            // Pin this exact panel by identity and require the observed unique
            // heading/close structure in the nearest ancestor, never Root().
            var panes=node.FindAll(TreeScope.Descendants,new OrCondition(
                new PropertyCondition(AutomationElement.AutomationIdProperty,"preferences-tab-content"),
                new PropertyCondition(AutomationElement.NameProperty,"Preferences panel")));
            int paneCount=0;bool exactPane=false;
            foreach(AutomationElement pane in panes) {
                if(pane.Current.IsOffscreen)continue;
                ++paneCount;if(Automation.Compare(pane,preferences))exactPane=true;
            }
            if(paneCount!=1 || !exactPane) {
                node=TreeWalker.ControlViewWalker.GetParent(node);continue;
            }
            var headings=node.FindAll(TreeScope.Descendants,
                new PropertyCondition(AutomationElement.NameProperty,"Settings"));
            int headingCount=0;
            foreach(AutomationElement heading in headings)
                if(!heading.Current.IsOffscreen)++headingCount;
            var closes=node.FindAll(TreeScope.Descendants,new AndCondition(
                new PropertyCondition(AutomationElement.ControlTypeProperty,ControlType.Button),
                new PropertyCondition(AutomationElement.NameProperty,"Close"),
                new PropertyCondition(AutomationElement.IsEnabledProperty,true)));
            int closeCount=0;
            foreach(AutomationElement close in closes)
                if(!close.Current.IsOffscreen)++closeCount;
            if(headingCount==1 && closeCount==1)return node;
            if(headingCount>1 || closeCount>1)
                throw new BridgeFailure("PreferencesSettingsDialogAmbiguous");
            node=TreeWalker.ControlViewWalker.GetParent(node);
        }
        throw new BridgeFailure("PreferencesSettingsDialogMissing");
    }
    static void InvokeExactPreferencesClose(AutomationElement preferences) {
        // SettingsScreen supplies the observed Settings heading and
        // Dialog.addCloseButton exposes the exact accessible label "Close".
        // Scope to that pane's ancestor, never other DevTools tab/drawer Xs.
        Foreground(Dev);
        AutomationElement dialog=ExactSettingsDialog(preferences);
        var buttons=dialog.FindAll(TreeScope.Descendants,new AndCondition(
            new PropertyCondition(AutomationElement.ControlTypeProperty,ControlType.Button),
            new PropertyCondition(AutomationElement.NameProperty,"Close"),
            new PropertyCondition(AutomationElement.IsEnabledProperty,true)));
        AutomationElement close=null;int visible=0;
        foreach(AutomationElement button in buttons) {
            if(button.Current.IsOffscreen)continue;
            close=button;++visible;
        }
        if(visible!=1)throw new BridgeFailure("PreferencesCloseMissingOrAmbiguous");
        object invoke;
        if(!close.TryGetCurrentPattern(InvokePattern.Pattern,out invoke))
            throw new BridgeFailure("PreferencesCloseInvokeUnavailable");
        Foreground(Dev);
        ((InvokePattern)invoke).Invoke();
    }
    static void CloseJavaScriptPreferences() {
        bool changed=CloseBoundedPreferences<AutomationElement>(
            VisiblePreferencesPane,InvokeExactPreferencesClose,
            delegate { return Clock.ElapsedMilliseconds; },Thread.Sleep,3500);
        PreferencesCloseMethod=changed?"official_settings_dialog_close_invoke":"already_closed";
    }
    static bool JavaScriptCheckboxState(bool? requested) {
        // Command Menu is only a navigator to a fixed Settings view, never a
        // state oracle. The SESSION setting is not stored in Preferences JSON.
        // A previous verified checkbox change may have succeeded while close
        // acknowledgement failed. Reuse that exact visible Settings pane for
        // rollback instead of sending Ctrl+Shift+P into a covering dialog.
        bool reusedPreferences=VisiblePreferencesPane()!=null;
        if(!reusedPreferences) {
            SelectConsole();
            MenuCommand("Show Preferences", false);
            WaitForPreferencesPane();
        }
        ToggleState initial = ReadJavaScriptCheckbox();
        ToggleState wanted = requested.HasValue
            ? (requested.Value ? ToggleState.On : ToggleState.Off) : initial;
        bool changed = false;
        if (requested.HasValue && initial != wanted) {
            AutomationElement checkbox = ExactJavaScriptCheckbox();
            if (checkbox.Current.IsOffscreen) {
                object scroll;
                if (!checkbox.TryGetCurrentPattern(ScrollItemPattern.Pattern, out scroll))
                    throw new BridgeFailure("JavaScriptCheckboxCannotScrollIntoView");
                Foreground(Dev);
                ((ScrollItemPattern)scroll).ScrollIntoView();
                Thread.Sleep(150);
                checkbox = ExactJavaScriptCheckbox();
            }
            if (checkbox.Current.IsOffscreen)
                throw new BridgeFailure("JavaScriptCheckboxNotVisible");
            object toggle;
            if (!checkbox.TryGetCurrentPattern(TogglePattern.Pattern, out toggle))
                throw new BridgeFailure("JavaScriptCheckboxToggleUnavailable");
            Foreground(Dev);
            // At most one direct, exact checkbox state change. No Enter/click
            // fallback or repeated toggle if acknowledgement is delayed.
            ((TogglePattern)toggle).Toggle();
            changed = true;
        }
        int stable = 0;
        long until = Clock.ElapsedMilliseconds + 6000;
        while (stable < 3 && Clock.ElapsedMilliseconds < until) {
            ToggleState observed = ReadJavaScriptCheckbox();
            stable = observed == wanted ? stable + 1 : 0;
            Thread.Sleep(150);
        }
        if (stable < 3) throw new BridgeFailure("JavaScriptCheckboxStateUnconfirmed");
        bool disabled = wanted == ToggleState.On;
        CloseJavaScriptPreferences();
        JavaScriptStateDiagnostic = new {javascriptDisabled=disabled,
            source="official_preferences_checkbox_toggle_pattern", samples=stable,
            changed=changed, scope="launcher_validated_remote_or_offline_inspector",
            preferencesPaneLocator=PreferencesPaneLocator,
            preferencesReused=reusedPreferences,preferencesCloseMethod=PreferencesCloseMethod,
            backendExecutionSeparatelyVerified=false};
        SelectConsole();
        return disabled;
    }
    static void JsState(bool disabled) {
        if (JavaScriptCheckboxState(disabled) != disabled)
            throw new BridgeFailure("JavaScriptCheckboxStateUnconfirmed");
    }
    static IntPtr FindDev() {
        var result = new List<IntPtr>();
        foreach (IntPtr w in OwnedWindows()) if (IsDevTitle(Title(w))) result.Add(w);
        if (result.Count > 1) throw new BridgeFailure("AmbiguousDevToolsWindows");
        return result.Count == 1 ? result[0] : IntPtr.Zero;
    }
    static void EnsureDev() {
        if(AlreadyForegroundOnly) {
            ValidateAlreadyForegroundTarget();
            return;
        }
        Dev = FindDev();
        if (Dev == IntPtr.Zero) {
            IntPtr main=IntPtr.Zero; long mainSeen=-1,readyUntil=Clock.ElapsedMilliseconds+12000;
            do {
                Dev=FindDev();
                if(Dev!=IntPtr.Zero) break;
                var mains=new List<IntPtr>();
                foreach(IntPtr w in OwnedWindows()) if(Title(w)=="Claude") mains.Add(w);
                if(mains.Count>1) throw new BridgeFailure("AmbiguousMainWindow");
                if(mains.Count==1) {
                    main=mains[0];
                    if(mainSeen<0) mainSeen=Clock.ElapsedMilliseconds;
                    // The launcher asks Claude itself to auto-open the remote
                    // inspector. Give it a bounded grace period before using
                    // the broader keyboard shortcut, which can open shell tools.
                    if(Clock.ElapsedMilliseconds-mainSeen>=4000) break;
                }
                Thread.Sleep(180);
            } while(Clock.ElapsedMilliseconds<readyUntil);
            if(Dev==IntPtr.Zero) {
                if(main==IntPtr.Zero) throw new BridgeFailure("MainWindowNotReady");
                Activate(main,false);
                // Auto-opening may finish while the main window is activated.
                // Reobserve once and issue the toggle at most once, only if absent.
                Dev=FindDev();
                if(Dev==IntPtr.Zero) {
                    Keys(main,false,0x11,0x12,0x49);
                    long until=Clock.ElapsedMilliseconds+12000;
                    do { Dev=FindDev(); if(Dev!=IntPtr.Zero) break; Thread.Sleep(180); } while(Clock.ElapsedMilliseconds<until);
                    if(Dev==IntPtr.Zero) throw new BridgeFailure("OfficialDevToolsUnavailable");
                }
            }
        }
        Activate(Dev, true);
    }
    static Condition OtherOptionCondition() {
        return new OrCondition(
            new PropertyCondition(AutomationElement.NameProperty,"Other\u2026"),
            new PropertyCondition(AutomationElement.NameProperty,"Other..."));
    }
    static AutomationElement OwnOtherOption() {
        // This query is scoped to the already-identified location combo only.
        return ById("location-select").FindFirst(TreeScope.Descendants,OtherOptionCondition());
    }
    static bool CustomLocationReady() {
        try {
            if (!IsOther(Value(ById("location-select")))) return false;
            AutomationElement timezone=Root().FindFirst(TreeScope.Descendants,
                new PropertyCondition(AutomationElement.AutomationIdProperty,"timezone-input"));
            AutomationElement locale=Root().FindFirst(TreeScope.Descendants,
                new PropertyCondition(AutomationElement.AutomationIdProperty,"locale-input"));
            return timezone!=null && locale!=null && timezone.Current.IsEnabled && locale.Current.IsEnabled;
        } catch (ElementNotAvailableException) { return false; }
    }
    static bool WaitCustomLocation(int milliseconds) {
        long until=Clock.ElapsedMilliseconds+milliseconds;
        do {
            Foreground(Dev);
            if (CustomLocationReady()) return true;
            Thread.Sleep(150);
        } while(Clock.ElapsedMilliseconds<until);
        return false;
    }
    static bool ObservedOtherAsPenultimate() {
        var items=ById("location-select").FindAll(TreeScope.Descendants,
            new PropertyCondition(AutomationElement.ControlTypeProperty,ControlType.ListItem));
        if(items.Count<2 || items.Count>64) return false;
        return IsOther(items[items.Count-2].Current.Name) &&
            items[items.Count-1].Current.Name=="Location unavailable";
    }
    static void SelectCustomLocation() {
        if (CustomLocationReady()) return;
        AutomationElement location=ById("location-select"); Focus(location);
        object pattern; bool expanded=false;
        if(location.TryGetCurrentPattern(ExpandCollapsePattern.Pattern,out pattern)) {
            try {
                Foreground(Dev);
                var expand=(ExpandCollapsePattern)pattern;
                if(expand.Current.ExpandCollapseState!=ExpandCollapseState.Expanded) expand.Expand();
                expanded=true;
            } catch(InvalidOperationException) { }
        }
        if(!expanded) Chord(Dev,0x12,0x28);
        AutomationElement option=null; long until=Clock.ElapsedMilliseconds+3500;
        do {
            Foreground(Dev); option=OwnOtherOption();
            if(option!=null) break;
            Thread.Sleep(150);
        } while(Clock.ElapsedMilliseconds<until);
        if(option==null) throw new BridgeFailure("CustomLocationOptionNotObserved");

        // Prefer semantic selection of this exact observed option. Managed .NET
        // UIA does not expose LegacyIAccessiblePattern on this installed runtime.
        bool selected=false;
        if(option.TryGetCurrentPattern(SelectionItemPattern.Pattern,out pattern)) {
            try { Foreground(Dev); ((SelectionItemPattern)pattern).Select(); selected=true; }
            catch(InvalidOperationException) { }
        }
        if(!selected && option.TryGetCurrentPattern(InvokePattern.Pattern,out pattern)) {
            try { Foreground(Dev); ((InvokePattern)pattern).Invoke(); selected=true; }
            catch(InvalidOperationException) { }
        }
        if(selected) {
            // Some native selects commit selection only when Enter closes them.
            if(IsOther(Value(ById("location-select")))) Chord(Dev,13);
            if(WaitCustomLocation(2500)) return;
        }

        // A bounded keyboard fallback is allowed only after observing the real
        // option order in this same combo: Other is the penultimate choice.
        // No letter matching, IME-dependent text input, coordinates or guesses.
        location=ById("location-select"); Focus(location);
        if(OwnOtherOption()==null) Chord(Dev,0x12,0x28);
        if(!ObservedOtherAsPenultimate()) throw new BridgeFailure("CustomLocationOptionOrderUnconfirmed");
        Chord(Dev,0x23); // End selects observed final Location unavailable.
        Chord(Dev,0x26); // Up selects the observed Other option immediately before it.
        Chord(Dev,13);
        if(!WaitCustomLocation(3500)) throw new BridgeFailure("CustomLocationNotSelected");
    }
    static void Configure() {
        MenuCommand("Show Sensors", false);
        SelectCustomLocation();
        SetField("latitude-input", "39.9526");
        SetField("longitude-input", "-75.1652");
        SetField("timezone-input", "America/New_York");
        SetField("locale-input", "en-US");
        SelectConsole();
    }
    static bool IsOther(string value) { return value == "Other\u2026" || value == "Other..."; }
    static Dictionary<string, object> ParseOwnMessage(string name, string nonce) {
        if (String.IsNullOrEmpty(name) || name.Length > 3000) return null;
        int start = name.IndexOf("{\"nonce\":\"" + nonce + "\"", StringComparison.Ordinal);
        if (start < 0) return null;
        int end = name.IndexOf('}', start);
        if (end < start) return null;
        try {
            var value = Json.Deserialize<Dictionary<string, object>>(name.Substring(start, end-start+1));
            if (value == null || !value.ContainsKey("nonce") || (string)value["nonce"] != nonce) return null;
            string[] keys = {"nonce","origin","topFrame","timeZone","language","januaryOffset","julyOffset","epoch"};
            if (value.Count != keys.Length) return null;
            foreach (string k in keys) if (!value.ContainsKey(k)) return null;
            long epoch = Convert.ToInt64(value["epoch"], CultureInfo.InvariantCulture);
            long now = (long)(DateTime.UtcNow-new DateTime(1970,1,1,0,0,0,DateTimeKind.Utc)).TotalMilliseconds;
            if (Math.Abs(now-epoch) > 15000) return null;
            string origin = Convert.ToString(value["origin"], CultureInfo.InvariantCulture);
            if (origin != "https://claude.ai" && origin != "null") throw new BridgeFailure("UnexpectedInspectedOrigin");
            if (!(value["topFrame"] is bool) || !(bool)value["topFrame"])
                throw new BridgeFailure("UnexpectedInspectedContext");
            return value;
        } catch (BridgeFailure) { throw; } catch { return null; }
    }
    static Dictionary<string, object> ReadOwnMessageTree(AutomationElement message, string marker, string nonce) {
        // Chromium may expose an outer group named exactly marker and a child
        // group containing marker + JSON. Stay inside that one marked message;
        // never enumerate its siblings or the surrounding console container.
        if (!message.Current.Name.StartsWith(marker,StringComparison.Ordinal)) return null;
        var queue = new Queue<KeyValuePair<AutomationElement,int>>();
        queue.Enqueue(new KeyValuePair<AutomationElement,int>(message,0));
        int queued=1, visited=0;
        while (queue.Count>0 && visited<64) {
            var item=queue.Dequeue(); ++visited; ++ProbeNodesVisited;
            string name=item.Key.Current.Name;
            // The containing message was already scoped by its exact marker.
            // Descendants can be a pure JSON text node without the marker prefix.
            var data=ParseOwnMessage(name,nonce);
            if (data!=null) return data;
            if (item.Value>=5) continue;
            AutomationElement child=TreeWalker.RawViewWalker.GetFirstChild(item.Key);
            while (child!=null && queued<64) {
                queue.Enqueue(new KeyValuePair<AutomationElement,int>(child,item.Value+1));
                ++queued;
                child=TreeWalker.RawViewWalker.GetNextSibling(child);
            }
        }
        return null;
    }
    static Dictionary<string, object> Verify() {
        SelectConsole();
        string nonce = Guid.NewGuid().ToString("N");
        string marker = "CLAUDE_TZ_GUARD_" + nonce;
        string expression = "console.log(\""+marker+"\",JSON.stringify({nonce:\""+nonce+"\",origin:location.origin,topFrame:self===top,timeZone:Intl.DateTimeFormat().resolvedOptions().timeZone,language:navigator.language,januaryOffset:new Date(\"2026-01-15T12:00:00Z\").getTimezoneOffset(),julyOffset:new Date(\"2026-07-15T12:00:00Z\").getTimezoneOffset(),epoch:Date.now()}))";
        AutomationElement prompt = ByName("Console prompt", "console-prompt");
        Set(prompt, expression); Chord(Dev, 13);
        long until = Clock.ElapsedMilliseconds + 12000;
        while (Clock.ElapsedMilliseconds < until) {
            Foreground(Dev);
            // Exact marker lookup is provider-side. Never enumerate/read page DOM,
            // console history, network messages or other console log text.
            AutomationElement markerElement = Root().FindFirst(TreeScope.Descendants,
                new PropertyCondition(AutomationElement.NameProperty, marker));
            if (markerElement != null) {
                ProbeMarkerFound=true;
                AutomationElement node = markerElement;
                for (int level=0; level<4 && node != null; ++level) {
                    string name = node.Current.Name;
                    // Only the marker's own message is allowed to be read.
                    if (!name.StartsWith(marker, StringComparison.Ordinal)) break;
                    Dictionary<string, object> data = ReadOwnMessageTree(node, marker, nonce);
                    if (data != null) return data;
                    node = TreeWalker.ControlViewWalker.GetParent(node);
                }
            }
            Thread.Sleep(180);
        }
        throw new BridgeFailure("MetadataNotReturnedOrPasteBlocked");
    }
    static bool ValidNonce(string value) {
        if(value==null || value.Length!=32) return false;
        foreach(char ch in value) if(!((ch>='0'&&ch<='9')||(ch>='a'&&ch<='f'))) return false;
        return true;
    }
    static string MonitorMetadata(string nonce) {
        if(!ValidNonce(nonce)) throw new BridgeFailure("MonitorNonceInvalid");
        return "JSON.stringify({nonce:\""+nonce+"\",origin:location.origin,topFrame:self===top,timeZone:Intl.DateTimeFormat().resolvedOptions().timeZone,language:navigator.language,januaryOffset:new Date(\"2026-01-15T12:00:00Z\").getTimezoneOffset(),julyOffset:new Date(\"2026-07-15T12:00:00Z\").getTimezoneOffset(),epoch:Date.now()})";
    }
    static string LiveMetadataExpression(string nonce) {
        // Official DevTools Live Expression evaluates this fixed pure expression
        // in the selected inspected page, not in a Worker or frontend context.
        return MonitorMetadata(nonce);
    }
    static Dictionary<string,object> ReadLive(string nonce,int milliseconds,bool foreground) {
        string expression=LiveMetadataExpression(nonce);
        string anchor="Remove expression: "+expression;
        string prefix="{\"nonce\":\""+nonce+"\"";
        long until=Clock.ElapsedMilliseconds+milliseconds;
        do {
            Alive();if(foreground)Foreground(Dev);
            AutomationElement own=Root().FindFirst(TreeScope.Descendants,
                new PropertyCondition(AutomationElement.NameProperty,anchor));
            if(own==null) {
                if(Clock.ElapsedMilliseconds<until){Thread.Sleep(100);continue;}
                throw new BridgeFailure("LiveExpressionNotInstalled");
            }
            // MatchSubstring is an official UIA condition since Windows 10 1809.
            // It is intentionally not a broad console/text enumeration: only
            // preview strings containing this exact JSON nonce prefix are read.
            var matches=Root().FindAll(TreeScope.Descendants,
                new PropertyCondition(AutomationElement.NameProperty,prefix,(PropertyConditionFlags)2));
            if(matches.Count>32)throw new BridgeFailure("LiveExpressionResultAmbiguous");
            Dictionary<string,object> latest=null;long epoch=0;
            foreach(AutomationElement item in matches) {
                var value=ParseOwnMessage(item.Current.Name,nonce);
                if(value!=null) {
                    long stamp=Convert.ToInt64(value["epoch"],CultureInfo.InvariantCulture);
                    if(stamp>epoch){latest=value;epoch=stamp;}
                }
            }
            long now=(long)(DateTime.UtcNow-new DateTime(1970,1,1,0,0,0,DateTimeKind.Utc)).TotalMilliseconds;
            if(latest!=null && Convert.ToString(latest["origin"],CultureInfo.InvariantCulture)=="https://claude.ai" && now-epoch>=0 && now-epoch<=4000)
                return latest;
            if(Clock.ElapsedMilliseconds<until)Thread.Sleep(100);
        }while(Clock.ElapsedMilliseconds<until);
        throw new BridgeFailure("LiveExpressionMissingOrStale");
    }
    static AutomationElement OwnLiveEditor(string nonce) {
        string expression=LiveMetadataExpression(nonce);
        if(Root().FindFirst(TreeScope.Descendants,new PropertyCondition(AutomationElement.NameProperty,
            "Remove expression: "+expression))==null) return null;
        var matches=Root().FindAll(TreeScope.Descendants,new AndCondition(
            new PropertyCondition(AutomationElement.NameProperty,"Live expression editor"),
            new PropertyCondition(ValuePattern.ValueProperty,expression)));
        if(matches.Count!=1)throw new BridgeFailure("OwnLiveExpressionEditorAmbiguous");
        return matches[0];
    }
    static void StopOwnedPulse() {
        // Migrate only this tool's old scheduling object. No Console clear,
        // history/profile reads, other timers, workers or user pins are touched.
        const string stop="(()=>{const k=Symbol.for(\"claude.network.guard.pulse.v1\"),o=globalThis[k];if(o&&(o.version===1||o.version===2)&&typeof o.nonce===\"string\"&&/^[a-f0-9]{32}$/.test(o.nonce)){if(o.timer)clearInterval(o.timer);if(o.worker)o.worker.terminate();if(typeof o.stop===\"function\")o.stop();delete globalThis[k]}return undefined})()";
        Set(ByName("Console prompt","console-prompt"),stop);Chord(Dev,13);
    }
    static int AppendedLiveEditorIndex(int before,int after) {
        if(before<0 || before>128 || after<0 || after>129)
            throw new BridgeFailure("TooManyLiveExpressionEditors");
        if(after<before || after>before+1)
            throw new BridgeFailure("NewLiveExpressionEditorCountChanged");
        return after==before ? -1 : before;
    }
    static bool EmptyLiveEditorValue(string value) {
        return String.IsNullOrWhiteSpace(value) ||
            String.Equals(value.Trim(),"Expression",StringComparison.Ordinal);
    }
    static Dictionary<string,object> LiveEditorDescriptor(int before,int after,int index,string value) {
        return new Dictionary<string,object> {
            {"before",before},{"after",after},{"chosenIndex",index},
            {"valueLength",value==null?0:value.Length},
            {"whitespaceOnly",String.IsNullOrWhiteSpace(value)},
            {"trimmedIsExpression",value!=null&&value.Trim()=="Expression"},
            {"startsWithOwnMetadata",value!=null&&value.TrimStart().StartsWith("JSON.stringify({nonce:\"",StringComparison.Ordinal)}
        };
    }
    static Dictionary<string,object> ArmLive(string nonce,string previous) {
        SelectConsole();StopOwnedPulse();
        string expression=LiveMetadataExpression(nonce);
        AutomationElement editor=OwnLiveEditor(nonce);
        if(editor==null && previous!=null)editor=OwnLiveEditor(previous);
        if(editor==null) {
            Condition editorCondition=new AndCondition(
                new PropertyCondition(AutomationElement.NameProperty,"Live expression editor"),
                new PropertyCondition(AutomationElement.ControlTypeProperty,ControlType.Edit));
            var before=Root().FindAll(TreeScope.Descendants,editorCondition);
            if(before.Count>128)throw new BridgeFailure("TooManyLiveExpressionEditors");
            int beforeCount=before.Count;
            AutomationElement create=Find(new AndCondition(
                new PropertyCondition(AutomationElement.NameProperty,"Create live expression"),
                new PropertyCondition(AutomationElement.ControlTypeProperty,ControlType.Button)),
                "create-live-expression",5000);
            object invoke;Foreground(Dev);
            if(create.TryGetCurrentPattern(InvokePattern.Pattern,out invoke))((InvokePattern)invoke).Invoke();
            else {Focus(create);Chord(Dev,13);}
            long until=Clock.ElapsedMilliseconds+5000;
            do {
                Foreground(Dev);
                // ConsolePinModel appends to its ordered Set; the pane renders
                // that insertion order. UIA FindAll preserves tree order. Do
                // not compare RuntimeIds: Chromium can rebuild old editors too.
                var after=Root().FindAll(TreeScope.Descendants,editorCondition);
                int addedIndex=AppendedLiveEditorIndex(beforeCount,after.Count);
                if(addedIndex>=0) {
                    // Confirm the count after rendering settles. Read only the
                    // appended editor's value; old user pin values stay unread.
                    Thread.Sleep(150);Foreground(Dev);
                    after=Root().FindAll(TreeScope.Descendants,editorCondition);
                    if(AppendedLiveEditorIndex(beforeCount,after.Count)!=addedIndex)
                        throw new BridgeFailure("NewLiveExpressionEditorCountChanged");
                    AutomationElement added=after[addedIndex];
                    string value=Value(added);
                    LiveArmDiagnostic=LiveEditorDescriptor(beforeCount,after.Count,addedIndex,value);
                    if(!EmptyLiveEditorValue(value))throw new BridgeFailure("NewLiveExpressionEditorNotEmpty");
                    editor=added;break;
                }
                Thread.Sleep(100);
            }while(Clock.ElapsedMilliseconds<until);
            if(editor==null)throw new BridgeFailure("NewLiveExpressionEditorNotFocused");
        }
        Set(editor,expression);Chord(Dev,13);
        // Enter commits and returns to the normal console prompt. Focusing it
        // explicitly also commits the exact fixed expression on blur.
        Focus(ByName("Console prompt","console-prompt"));
        return ReadLive(nonce,8000,true);
    }
    static Dictionary<string, object> ReadMonitor(string nonce, int milliseconds, bool foreground) {
        long until=Clock.ElapsedMilliseconds+milliseconds;
        do {
            Alive();
            if(foreground) Foreground(Dev);
            foreach(string kind in new[]{"CSP","UNAVAILABLE"}) {
                string errorMarker="CLAUDE_ENV_PULSE_ERROR_"+kind+"_"+nonce;
                var error=Root().FindFirst(TreeScope.Descendants,
                    new PropertyCondition(AutomationElement.NameProperty,errorMarker));
                if(error!=null) throw new BridgeFailure(kind=="CSP"?"MonitorWorkerCspBlocked":"MonitorWorkerUnavailable");
            }
            Dictionary<string,object> latest=null; long latestEpoch=0;
            long queryEpoch=(long)(DateTime.UtcNow-new DateTime(1970,1,1,0,0,0,DateTimeKind.Utc)).TotalMilliseconds;
            // Each second has a distinct exact marker. This avoids similar-log
            // folding of one constant marker and bounds lookup to six seconds.
            foreach(string marker in MonitorMarkers(nonce,queryEpoch)) {
                var exact=Root().FindAll(TreeScope.Descendants,
                    new PropertyCondition(AutomationElement.NameProperty,marker));
                for(int i=exact.Count-1;i>=Math.Max(0,exact.Count-8);--i) {
                    AutomationElement node=exact[i];
                    for(int level=0;level<4 && node!=null;++level) {
                        if(!node.Current.Name.StartsWith(marker,StringComparison.Ordinal)) break;
                        var data=ReadOwnMessageTree(node,marker,nonce);
                        if(data!=null) {
                            long epoch=Convert.ToInt64(data["epoch"],CultureInfo.InvariantCulture);
                            if(epoch>latestEpoch) { latest=data;latestEpoch=epoch; }
                            break;
                        }
                        node=TreeWalker.ControlViewWalker.GetParent(node);
                    }
                }
                if(latest!=null) break;
            }
            if(latest!=null) {
                long now=(long)(DateTime.UtcNow-new DateTime(1970,1,1,0,0,0,DateTimeKind.Utc)).TotalMilliseconds;
                if(Convert.ToString(latest["origin"],CultureInfo.InvariantCulture)!="https://claude.ai")
                    throw new BridgeFailure("UnexpectedInspectedOrigin");
                if(now-latestEpoch>=0 && now-latestEpoch<=4000) return latest;
            }
            if(Clock.ElapsedMilliseconds<until) Thread.Sleep(100);
        } while(Clock.ElapsedMilliseconds<until);
        throw new BridgeFailure("MonitorHeartbeatMissingOrStale");
    }
    static string[] MonitorMarkers(string nonce,long epoch) {
        if(!ValidNonce(nonce) || epoch<0) throw new BridgeFailure("MonitorNonceInvalid");
        string[] result=new string[6];long bucket=epoch/1000;
        for(int i=0;i<result.Length;++i)
            result[i]="CLAUDE_ENV_PULSE_"+nonce+"_"+(bucket-i).ToString(CultureInfo.InvariantCulture);
        return result;
    }
    static string WorkerMonitorExpression(string nonce) {
        string metadata=MonitorMetadata(nonce).Replace("epoch:Date.now()","epoch:epoch");
        string prefix="CLAUDE_ENV_PULSE_"+nonce+"_";
        // The Worker only schedules ticks; it does not report its own locale.
        // Every tick reads fresh main-page Intl/navigator/Date synchronously.
        // No HTTP/socket request, account/DOM read, or CSP relaxation is used.
        return "(()=>{const k=Symbol.for(\"claude.network.guard.pulse.v1\");const old=globalThis[k];if(old&&(old.version===1||old.version===2)&&typeof old.nonce===\"string\"&&/^[a-f0-9]{32}$/.test(old.nonce)){if(old.timer)clearInterval(old.timer);if(old.worker)old.worker.terminate();if(typeof old.stop===\"function\")old.stop()}let worker=null,url=null,failed=false,ready=false,lastBucket=-1;const cleanup=()=>{document.removeEventListener(\"securitypolicyviolation\",policy);if(url){URL.revokeObjectURL(url);url=null}};const fail=kind=>{if(failed)return;failed=true;if(worker)worker.terminate();cleanup();console.log(\"CLAUDE_ENV_PULSE_ERROR_\"+kind+\"_"+nonce+"\",\"worker unavailable\")};const policy=e=>{if(!ready&&(e.blockedURI===url||e.blockedURI===\"blob\"||e.blockedURI===\"blob:\"))fail(\"CSP\")};const emit=()=>{if(failed)return;ready=true;cleanup();const epoch=Date.now(),bucket=Math.floor(epoch/1000);if(bucket===lastBucket)return;lastBucket=bucket;console.log(\""+prefix+"\"+bucket,"+metadata+")};document.addEventListener(\"securitypolicyviolation\",policy);try{url=URL.createObjectURL(new Blob([\"self.postMessage(0);setInterval(()=>self.postMessage(0),1000)\"],{type:\"application/javascript\"}));worker=new Worker(url);worker.onmessage=emit;worker.onerror=()=>fail(\"UNAVAILABLE\");globalThis[k]={version:2,nonce:\""+nonce+"\",worker,stop:()=>{failed=true;if(worker)worker.terminate();cleanup()}}}catch{fail(\"UNAVAILABLE\")}return undefined;})()";
    }
    static Dictionary<string, object> ArmMonitor(string nonce) {
        SelectConsole();
        string expression=WorkerMonitorExpression(nonce);
        Set(ByName("Console prompt","console-prompt"),expression); Chord(Dev,13);
        return ReadMonitor(nonce,8000,true);
    }
    static Dictionary<string,object> NetworkConfig(string configPath,string root) {
        string full=Path.GetFullPath(configPath);
        string boundary=Path.Combine(root,"privacy-qa","runs")+Path.DirectorySeparatorChar;
        if(!String.Equals(full,configPath,StringComparison.OrdinalIgnoreCase) ||
            !full.StartsWith(boundary,StringComparison.OrdinalIgnoreCase) ||
            !File.Exists(full) || new FileInfo(full).Length>4096)
            throw new BridgeFailure("NetworkConfigPathInvalid");
        string cursor=full;
        while(cursor!=null && cursor.StartsWith(root,StringComparison.OrdinalIgnoreCase)) {
            if((File.GetAttributes(cursor)&FileAttributes.ReparsePoint)!=0)
                throw new BridgeFailure("NetworkConfigPathRedirected");
            if(String.Equals(cursor,root,StringComparison.OrdinalIgnoreCase)) break;
            cursor=Path.GetDirectoryName(cursor);
        }
        var config=Json.Deserialize<Dictionary<string,object>>(File.ReadAllText(full,Encoding.UTF8));
        string[] keys={"schema_version","nonce","ipv4","udp4_port","ipv6","tcp6_port"};
        if(config==null || config.Count!=keys.Length) throw new BridgeFailure("NetworkConfigInvalid");
        foreach(string key in keys) if(!config.ContainsKey(key)) throw new BridgeFailure("NetworkConfigInvalid");
        if(!(config["schema_version"] is int) || (int)config["schema_version"]!=1 ||
            !(config["nonce"] is string) || !ValidNonce((string)config["nonce"]) ||
            !(config["ipv4"] is string) || !(config["ipv6"] is string) || (string)config["ipv6"]!="::1")
            throw new BridgeFailure("NetworkConfigInvalid");
        foreach(string key in new[]{"udp4_port","tcp6_port"})
            if(!(config[key] is int) || (int)config[key]<1 || (int)config[key]>65535)
                throw new BridgeFailure("NetworkConfigInvalid");
        IPAddress address;
        if(!IPAddress.TryParse((string)config["ipv4"],out address) || address.AddressFamily!=System.Net.Sockets.AddressFamily.InterNetwork ||
            address.ToString()!=(string)config["ipv4"])
            throw new BridgeFailure("NetworkConfigAddressInvalid");
        byte[] bytes=address.GetAddressBytes();
        bool privateAddress=bytes[0]==10 || bytes[0]==127 || (bytes[0]==192&&bytes[1]==168) ||
            (bytes[0]==172&&bytes[1]>=16&&bytes[1]<=31);
        bool local=IPAddress.IsLoopback(address);
        foreach(NetworkInterface nic in NetworkInterface.GetAllNetworkInterfaces())
            foreach(UnicastIPAddressInformation item in nic.GetIPProperties().UnicastAddresses)
                if(item.Address.Equals(address)) local=true;
        if(!privateAddress || !local) throw new BridgeFailure("NetworkConfigAddressNotLocal");
        return config;
    }
    static string NetworkExpression(Dictionary<string,object> config) {
        string nonce=(string)config["nonce"],marker="CLAUDE_NET_QA_"+nonce;
        string stun=Json.Serialize("stun:"+(string)config["ipv4"]+":"+Convert.ToString(config["udp4_port"],CultureInfo.InvariantCulture));
        // Never fetch an IPv6 loopback URL through the residential proxy. That
        // probes the remote machine's loopback, not this app's local WFP identity.
        return "(async()=>{const r={nonce:\""+nonce+"\",origin:location.origin,topFrame:self===top,rtcSupported:typeof RTCPeerConnection===\"function\",rtcCompleted:false,rtcGatherComplete:false,rtcCandidateCount:0,rtcUdpCandidates:0,rtcTcpCandidates:0,rtcPublicV4Candidates:0,rtcPublicV4OutsideAllowlist:0,rtcPublicV4AllAllowed:true,rtcPrivateAddressCandidates:0,rtcLoopbackCandidates:0,rtcMdnsCandidates:0,rtcIpv6LinkLocalCandidates:0,rtcGlobalIpv6Candidates:0,rtcReservedAddressCandidates:0,rtcUnclassifiedCandidates:0,ipv6Attempted:false,ipv6Settled:false,ipv6Outcome:\"proxy_path_not_kernel_probe\",ipv6CspBlocked:false,epoch:0};"+NetworkAddressClassifier()+"if(r.rtcSupported){await new Promise(resolve=>{let pc,timer,done=false;const finish=()=>{if(done)return;done=true;clearTimeout(timer);if(pc){pc.onicecandidate=null;pc.onicegatheringstatechange=null;pc.close()}r.rtcCompleted=true;resolve()};timer=setTimeout(finish,4000);try{pc=new RTCPeerConnection({iceServers:[{urls:"+stun+"}]});pc.onicecandidate=e=>{if(e.candidate){r.rtcCandidateCount++;classify(e.candidate);if(e.candidate.protocol===\"udp\")r.rtcUdpCandidates++;if(e.candidate.protocol===\"tcp\")r.rtcTcpCandidates++}else{r.rtcGatherComplete=true;finish()}};pc.onicegatheringstatechange=()=>{if(pc.iceGatheringState===\"complete\"){r.rtcGatherComplete=true;finish()}};pc.createDataChannel(\"claude-local-qa\");pc.createOffer().then(o=>pc.setLocalDescription(o)).catch(()=>{if(!done){done=true;clearTimeout(timer);pc.close();resolve()}})}catch{done=true;clearTimeout(timer);if(pc)pc.close();resolve()}})}r.epoch=Date.now();console.log(\""+marker+"\",JSON.stringify(r))})()";
    }
    static string NetworkAddressClassifier() {
        // Classify only; never print/store candidate IP addresses or identifiers.
        return "const classify=c=>{let s=String(c.address||String(c.candidate||\"\").split(/\\s+/)[4]||\"\").toLowerCase();if(s.endsWith(\".local\")||s.endsWith(\".local.\")){r.rtcMdnsCandidates++;return}if(s.startsWith(\"::ffff:\")&&s.includes(\".\"))s=s.slice(7);if(/^\\d{1,3}(?:\\.\\d{1,3}){3}$/.test(s)){const a=s.split(\".\").map(Number);if(a.some(x=>x>255)){r.rtcUnclassifiedCandidates++;return}if(a[0]===127){r.rtcLoopbackCandidates++;return}if(a[0]===10||(a[0]===172&&a[1]>=16&&a[1]<=31)||(a[0]===192&&a[1]===168)||(a[0]===169&&a[1]===254)||(a[0]===100&&a[1]>=64&&a[1]<=127)){r.rtcPrivateAddressCandidates++;return}if(a[0]===0||a[0]>=224||(a[0]===192&&a[1]===0&&(a[2]===0||a[2]===2))||(a[0]===198&&(a[1]===18||a[1]===19||(a[1]===51&&a[2]===100)))||(a[0]===203&&a[1]===0&&a[2]===113)){r.rtcReservedAddressCandidates++;return}r.rtcPublicV4Candidates++;if(true){r.rtcPublicV4OutsideAllowlist++;r.rtcPublicV4AllAllowed=false}return}if(s===\"::1\"||s===\"0:0:0:0:0:0:0:1\"){r.rtcLoopbackCandidates++;return}if(/^fe[89ab][0-9a-f]:/.test(s)){r.rtcIpv6LinkLocalCandidates++;return}if(/^f[cd][0-9a-f]{2}:/.test(s)){r.rtcPrivateAddressCandidates++;return}if(/^[23][0-9a-f]{3}:/.test(s)){r.rtcGlobalIpv6Candidates++;return}if(s===\"::\"||s===\"0:0:0:0:0:0:0:0\"){r.rtcReservedAddressCandidates++;return}r.rtcUnclassifiedCandidates++};";
    }
    static Dictionary<string,object> ParseNetworkMessage(string name,string nonce) {
        if(String.IsNullOrEmpty(name)||name.Length>4000) return null;
        int start=name.IndexOf("{\"nonce\":\""+nonce+"\"",StringComparison.Ordinal);
        int end=start<0?-1:name.IndexOf('}',start);
        if(end<start || start<0) return null;
        try {
            var data=Json.Deserialize<Dictionary<string,object>>(name.Substring(start,end-start+1));
            string[] keys={"nonce","origin","topFrame","rtcSupported","rtcCompleted","rtcGatherComplete","rtcCandidateCount","rtcUdpCandidates","rtcTcpCandidates","rtcPublicV4Candidates","rtcPublicV4OutsideAllowlist","rtcPublicV4AllAllowed","rtcPrivateAddressCandidates","rtcLoopbackCandidates","rtcMdnsCandidates","rtcIpv6LinkLocalCandidates","rtcGlobalIpv6Candidates","rtcReservedAddressCandidates","rtcUnclassifiedCandidates","ipv6Attempted","ipv6Settled","ipv6Outcome","ipv6CspBlocked","epoch"};
            if(data==null || data.Count!=keys.Length) return null;
            foreach(string key in keys) if(!data.ContainsKey(key)) return null;
            if(!(data["nonce"] is string) || (string)data["nonce"]!=nonce ||
                !(data["origin"] is string) || (string)data["origin"]!="https://claude.ai" ||
                !(data["topFrame"] is bool) || !(bool)data["topFrame"])
                throw new BridgeFailure("NetworkProbeContextUnexpected");
            foreach(string key in new[]{"rtcSupported","rtcCompleted","rtcGatherComplete","rtcPublicV4AllAllowed","ipv6Attempted","ipv6Settled","ipv6CspBlocked"})
                if(!(data[key] is bool)) return null;
            foreach(string key in new[]{"rtcCandidateCount","rtcUdpCandidates","rtcTcpCandidates","rtcPublicV4Candidates","rtcPublicV4OutsideAllowlist","rtcPrivateAddressCandidates","rtcLoopbackCandidates","rtcMdnsCandidates","rtcIpv6LinkLocalCandidates","rtcGlobalIpv6Candidates","rtcReservedAddressCandidates","rtcUnclassifiedCandidates"})
                if(!(data[key] is int) || (int)data[key]<0 || (int)data[key]>10000) return null;
            int classified=0;
            foreach(string key in new[]{"rtcPublicV4Candidates","rtcPrivateAddressCandidates","rtcLoopbackCandidates","rtcMdnsCandidates","rtcIpv6LinkLocalCandidates","rtcGlobalIpv6Candidates","rtcReservedAddressCandidates","rtcUnclassifiedCandidates"}) classified+=(int)data[key];
            if(classified!=(int)data["rtcCandidateCount"] ||
                (int)data["rtcPublicV4OutsideAllowlist"]>(int)data["rtcPublicV4Candidates"] ||
                (bool)data["rtcPublicV4AllAllowed"]!=((int)data["rtcPublicV4OutsideAllowlist"]==0) ||
                (int)data["rtcUdpCandidates"]+(int)data["rtcTcpCandidates"]>(int)data["rtcCandidateCount"]) return null;
            if(!(data["ipv6Outcome"] is string) || (string)data["ipv6Outcome"]!="proxy_path_not_kernel_probe" ||
                (bool)data["ipv6Attempted"] || (bool)data["ipv6Settled"]) return null;
            long now=(long)(DateTime.UtcNow-new DateTime(1970,1,1,0,0,0,DateTimeKind.Utc)).TotalMilliseconds;
            if(Math.Abs(now-Convert.ToInt64(data["epoch"],CultureInfo.InvariantCulture))>15000) return null;
            return data;
        }catch(BridgeFailure){throw;}catch{return null;}
    }
    static Dictionary<string,object> NetworkCheck(Dictionary<string,object> config) {
        SelectConsole();
        string nonce=(string)config["nonce"],marker="CLAUDE_NET_QA_"+nonce;
        Set(ByName("Console prompt","console-prompt"),NetworkExpression(config));Chord(Dev,13);
        long until=Clock.ElapsedMilliseconds+14000;
        do {
            Foreground(Dev);
            AutomationElement element=Root().FindFirst(TreeScope.Descendants,new PropertyCondition(AutomationElement.NameProperty,marker));
            if(element!=null) {
                AutomationElement node=element;
                for(int level=0;level<4&&node!=null;++level) {
                    if(!node.Current.Name.StartsWith(marker,StringComparison.Ordinal)) break;
                    var queue=new Queue<KeyValuePair<AutomationElement,int>>();queue.Enqueue(new KeyValuePair<AutomationElement,int>(node,0));int count=1;
                    while(queue.Count>0) {
                        var current=queue.Dequeue();var data=ParseNetworkMessage(current.Key.Current.Name,nonce);if(data!=null)return data;
                        if(current.Value>=5)continue;
                        AutomationElement child=TreeWalker.RawViewWalker.GetFirstChild(current.Key);
                        while(child!=null&&count<64){queue.Enqueue(new KeyValuePair<AutomationElement,int>(child,current.Value+1));++count;child=TreeWalker.RawViewWalker.GetNextSibling(child);}
                    }
                    node=TreeWalker.ControlViewWalker.GetParent(node);
                }
            }
            Thread.Sleep(150);
        }while(Clock.ElapsedMilliseconds<until);
        throw new BridgeFailure("NetworkProbeResultUnavailable");
    }
    static object RecoverMinimized(string expectedHwnd,string nonce) {
        long hwnd;
        if(!Int64.TryParse(expectedHwnd,NumberStyles.None,CultureInfo.InvariantCulture,out hwnd) || hwnd<=0)
            throw new BridgeFailure("ExpectedWindowInvalid");
        Dev=new IntPtr(hwnd);
        // No EnsureDev, Activate, SendInput or settings edits. The command can
        // touch only the exact pre-observed existing window of the pinned main.
        CheckWindow(Dev,true);
        if(!IsOwnChromeWindow(Dev) || FindDev()!=Dev || !IsWindowVisible(Dev))
            throw new BridgeFailure("ExpectedMonitorWindowChanged");
        NoModal();
        IntPtr foregroundBefore=GetForegroundWindow();
        if(!IsIconic(Dev)) return new {recovered=false,hwnd=hwnd,visible=IsWindowVisible(Dev),
            minimized=false,foregroundPreserved=foregroundBefore==GetForegroundWindow(),ownMetadataPresent=false};
        Alive();CheckWindow(Dev,true);
        if(!IsIconic(Dev)) throw new BridgeFailure("MonitorNoLongerMinimized");
        ShowWindow(Dev,4); // SW_SHOWNOACTIVATE, never activates the app.
        if(!SetWindowPos(Dev,new IntPtr(1),0,0,0,0,0x0213))
            throw new BridgeFailure("CannotParkInspectorAtBottom");
        Thread.Sleep(180);CheckWindow(Dev,true);
        if(FindDev()!=Dev || !IsOwnChromeWindow(Dev) || !IsWindowVisible(Dev) || IsIconic(Dev))
            throw new BridgeFailure("MonitorRecoveryUnconfirmed");
        if(GetForegroundWindow()!=foregroundBefore)
            throw new BridgeFailure("RecoveryForegroundChanged");
        // Proof only that our existing nonce-bound metadata is available again;
        // the watchdog separately validates freshness, timezone and language.
        ReadLive(nonce,1000,false);
        return new {recovered=true,hwnd=hwnd,visible=true,minimized=false,
            foregroundPreserved=foregroundBefore==GetForegroundWindow(),ownMetadataPresent=true};
    }
    static object Inspect() {
        var windows = new List<object>();
        foreach (IntPtr w in OwnedWindows()) {
            string kind = Kind(w);
            if (kind != "other") windows.Add(new {kind=kind, hwnd=w.ToInt64(), visible=IsWindowVisible(w), minimized=IsIconic(w)});
        }
        return new {windows=windows.ToArray()};
    }
    static void Result(bool ok, string error, object data) {
        if (Interlocked.CompareExchange(ref Finished, 1, 0) != 0) return;
        Console.WriteLine(Json.Serialize(new {ok=ok, command=Command, pid=Pid, error=error, data=data}));
        Console.Out.Flush();
    }
    const string ForegroundGrantFlag="--foreground-grant-v2";
    const string ForegroundGrantProtocol="claude-foreground-grant-v2";
    const string ForegroundGrantToken="CLAUDE_FOREGROUND_GRANTED_V2";
    const string AlreadyForegroundToken="CLAUDE_ALREADY_TARGET_FOREGROUND_V2";
    static bool ForegroundGrantRequested(string[] args) {
        bool requested=args.Length>0&&args[args.Length-1]==ForegroundGrantFlag;
        for(int i=0;i<args.Length-(requested?1:0);++i)
            if(args[i]==ForegroundGrantFlag || args[i]=="--foreground-grant-v1")
                throw new BridgeFailure("ForegroundGrantFlagInvalid");
        return requested;
    }
    static bool ForegroundCommand(string command) {
        return Commands.Contains(command) && command!="inspect" && command!="inspect-main-inspector-menu" && command!="poll-live" &&
            command!="poll-monitor" && command!="park-monitor" && command!="park-monitor-bottom" && command!="hide" &&
            command!="recover-minimized-monitor";
    }
    static object ForegroundReadyEnvelope(string command,int pid,int helperPid,long creation,bool alreadyForeground) {
        return new {protocol=ForegroundGrantProtocol,ready=true,command=command,pid=pid,
            helperPid=helperPid,targetCreation=((ulong)creation).ToString("x16",CultureInfo.InvariantCulture),
            exactTargetDevToolsAlreadyForeground=alreadyForeground};
    }
    static int ReadForegroundGrantToken(TextReader input) {
        // Only two fixed tokens plus LF or CRLF then EOF. No unbounded ReadLine.
        var value=new StringBuilder();
        for(int i=0;i<=64;++i) {
            int next=input.Read();
            if(next<0)return 0;
            if(next=='\n' || next=='\r') {
                if(next=='\r' && input.Read()!='\n')return 0;
                if(input.Read()>=0)return 0;
                string token=value.ToString();
                return token==ForegroundGrantToken ? 1 : token==AlreadyForegroundToken ? 2 : 0;
            }
            value.Append((char)next);
        }
        return 0;
    }
    static bool CaptureAlreadyForegroundTarget() {
        if(Command=="main-inspector" || Command=="main-inspector-close")return CaptureMainInspectorForeground();
        // Win32 identity metadata only. No UI Automation, focus, input or settings.
        ForegroundReadyDev=IntPtr.Zero;
        IntPtr candidate=FindDev();
        if(candidate==IntPtr.Zero || GetForegroundWindow()!=candidate)return false;
        Dev=candidate;
        CheckWindow(candidate,true);NoModal();
        if(!IsWindowVisible(candidate) || !IsWindowEnabled(candidate) || IsIconic(candidate) ||
            GetForegroundWindow()!=candidate)return false;
        ForegroundReadyDev=candidate;
        return true;
    }
    static void ValidateAlreadyForegroundTarget() {
        if(Command=="main-inspector" || Command=="main-inspector-close") {ValidateMainInspectorForeground();return;}
        // Never activate a different/new/restored window in the no-grant branch.
        Alive();
        if(ForegroundReadyDev==IntPtr.Zero || FindDev()!=ForegroundReadyDev)
            throw new BridgeFailure("AlreadyForegroundTargetChanged");
        Dev=ForegroundReadyDev;
        CheckWindow(Dev,true);NoModal();
        if(!IsWindowVisible(Dev) || !IsWindowEnabled(Dev) || IsIconic(Dev) || GetForegroundWindow()!=Dev)
            throw new BridgeFailure("AlreadyForegroundTargetChanged");
    }
    static bool AlreadyForegroundTokenAllowed(int token,bool readyAlreadyForeground) {
        return token==1 || (token==2 && readyAlreadyForeground);
    }
    static void WaitForForegroundGrant() {
        // An exact window the user already put in front does not need activation
        // permission. Bind its HWND before ready and recheck after the fixed token.
        bool alreadyForeground=CaptureAlreadyForegroundTarget();
        Console.Out.WriteLine(Json.Serialize(ForegroundReadyEnvelope(Command,Pid,Process.GetCurrentProcess().Id,ProcessCreated,alreadyForeground)));
        Console.Out.Flush();
        Task<int> token=Task.Factory.StartNew(()=>ReadForegroundGrantToken(Console.In));
        if(!token.Wait(5000))throw new BridgeFailure("ForegroundGrantTimeout");
        if(!AlreadyForegroundTokenAllowed(token.Result,alreadyForeground))
            throw new BridgeFailure("ForegroundGrantRejected");
        if(token.Result==2) {
            AlreadyForegroundOnly=true;
            ValidateAlreadyForegroundTarget();
        }
    }
    [STAThread] static int Main(string[] args) {
        try {
            bool foregroundGrant=ForegroundGrantRequested(args);
            if(foregroundGrant)Array.Resize(ref args,args.Length-1);
            if ((args.Length != 2 && args.Length != 3 && args.Length != 4 && args.Length != 5) || !Commands.Contains(args[0]) || !Int32.TryParse(args[1], out Pid) || Pid <= 0)
                throw new BridgeFailure("Usage:DevToolsUi.exe-command-mainPID-creationHex");
            Command = args[0];
            if(foregroundGrant&&!ForegroundCommand(Command))throw new BridgeFailure("ForegroundGrantCommandInvalid");
            bool mainInspector=Command=="main-inspector" || Command=="main-inspector-close";
            if(mainInspector && (!foregroundGrant || args.Length!=3))
                throw new BridgeFailure("MainInspectorForegroundHandshakeRequired");
            bool monitor=Command=="arm-monitor" || Command=="poll-monitor";
            bool live=Command=="arm-live" || Command=="poll-live";
            bool network=Command=="network-check";
            bool recover=Command=="recover-minimized-monitor";
            if(monitor ? (args.Length!=4 || !ValidNonce(args[3])) :
                live ? (args.Length<4 || args.Length>5 || !ValidNonce(args[3]) ||
                    (args.Length==5 && (Command!="arm-live" || !ValidNonce(args[4])))) :
                network ? args.Length!=4 :
                recover ? (args.Length!=5 || !ValidNonce(args[4])) : args.Length>3)
                throw new BridgeFailure("MonitorNonceInvalid");
            ulong expectedCreation=0;
            if (Command != "inspect" && args.Length < 3)
                throw new BridgeFailure("ExpectedCreationRequired");
            if (args.Length >= 3 && (args[2].Length != 16 ||
                !UInt64.TryParse(args[2],NumberStyles.AllowHexSpecifier,CultureInfo.InvariantCulture,out expectedCreation) || expectedCreation == 0))
                throw new BridgeFailure("ExpectedCreationInvalid");
            ProcessHandle = OpenProcess(QueryLimited, false, Pid);
            if (ProcessHandle == IntPtr.Zero) throw new BridgeFailure("CannotInspectMainProcess");
            FileTime c,e,k,u;
            if (!GetProcessTimes(ProcessHandle, out c, out e, out k, out u)) throw new BridgeFailure("CannotPinProcessIdentity");
            ProcessCreated=Stamp(c);
            if (args.Length >= 3 && (ulong)ProcessCreated != expectedCreation)
                throw new BridgeFailure("MainProcessCreationMismatch");
            var b = new StringBuilder(32768); int size = b.Capacity;
            if (!QueryFullProcessImageName(ProcessHandle, 0, b, ref size)) throw new BridgeFailure("CannotValidateExecutable");
            string path = b.ToString();
            string root = Directory.GetParent(Path.GetDirectoryName(typeof(DevToolsUi).Assembly.Location)).FullName;
            string marker = Path.Combine(root,"installed.json");
            if (!File.Exists(marker) || new FileInfo(marker).Length > 1048576) throw new BridgeFailure("InstalledMarkerUnavailable");
            var installed = Json.Deserialize<Dictionary<string,object>>(File.ReadAllText(marker,Encoding.UTF8));
            string package = installed.ContainsKey("package") ? installed["package"] as string : null;
            if (String.IsNullOrEmpty(package) || package.Length > 300 || Path.GetFileName(package) != package ||
                !package.StartsWith("Claude_",StringComparison.Ordinal) || !package.EndsWith("__pzs8sxrjxfjjc",StringComparison.Ordinal))
                throw new BridgeFailure("InstalledMarkerInvalid");
            string expected = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),"WindowsApps",package,"app","Claude.exe");
            if (!String.Equals(path,expected,StringComparison.OrdinalIgnoreCase))
                throw new BridgeFailure("UnexpectedExecutable");
            ExpectedLocalFrontend=Path.GetFullPath(Path.Combine(Path.GetDirectoryName(expected),
                "resources","app.asar",".vite","renderer","main_window","index.html"));
            Dictionary<string,object> networkConfig=network ? NetworkConfig(args[3],root) : null;
            Deadline = new Timer(delegate(object state) {
                Result(false,"CommandHardDeadline",null); Environment.Exit(2);
            }, null, 60000, Timeout.Infinite);
            if(foregroundGrant)WaitForForegroundGrant();
            object result;
            if (Command == "inspect") result=Inspect();
            else if(Command=="inspect-main-inspector-menu")result=MainInspectorMenuDiagnostic();
            else if(Command=="main-inspector" || Command=="main-inspector-close")
                result=MainInspector(Command=="main-inspector");
            else if(Command=="recover-minimized-monitor") result=RecoverMinimized(args[3],args[4]);
            else if(Command=="poll-live") {
                Dev=FindDev();if(Dev==IntPtr.Zero)throw new BridgeFailure("DevToolsNotRunning");
                result=ReadLive(args[3],500,false);
            }
            else if(Command=="park-monitor" || Command=="park-monitor-bottom") {
                // A hidden Chromium window can stop exposing live UIA nodes.
                // Keep the existing inspector accessible without changing the
                // main window, moving the pointer, activating or sending input.
                Dev=FindDev(); if(Dev==IntPtr.Zero) throw new BridgeFailure("DevToolsNotRunning");
                CheckWindow(Dev,true);
                IntPtr foregroundBefore=GetForegroundWindow();
                bool bottom=Command=="park-monitor-bottom";
                if(bottom) {
                    ShowWindow(Dev,4); // SW_SHOWNOACTIVATE.
                    if(!SetWindowPos(Dev,new IntPtr(1),0,0,0,0,0x0213))
                        throw new BridgeFailure("CannotParkInspectorAtBottom");
                } else ShowWindow(Dev,7); // SW_SHOWMINNOACTIVE.
                Thread.Sleep(180);CheckWindow(Dev,true);
                bool visible=IsWindowVisible(Dev),minimized=IsIconic(Dev);
                if(!visible || (!bottom && !minimized) || (bottom && minimized))
                    throw new BridgeFailure("InspectorParkingUnconfirmed");
                result=new {parked=true,mode=bottom?"bottom_no_activate":"minimized_no_activate",
                    visible=visible,minimized=minimized,hwnd=Dev.ToInt64(),
                    foregroundPreserved=foregroundBefore==GetForegroundWindow()};
            }
            else if(Command=="poll-monitor") {
                // No activation, foreground input, inspector creation or settings.
                Dev=FindDev(); if(Dev==IntPtr.Zero) throw new BridgeFailure("DevToolsNotRunning");
                result=ReadMonitor(args[3],500,false);
            }
            else if (Command == "hide") {
                Dev=FindDev(); if(Dev==IntPtr.Zero) throw new BridgeFailure("DevToolsNotRunning");
                CheckWindow(Dev,true); ShowWindow(Dev,0); int auxiliaryHidden=HideAuxiliaryDevTools();
                result=new {hidden=!IsWindowVisible(Dev),hwnd=Dev.ToInt64(),auxiliaryHidden=auxiliaryHidden};
            } else {
                EnsureDev();
                switch(Command) {
                    case "configure": Configure(); result=new {configured=true}; break;
                    case "verify": result=Verify(); break;
                    case "arm-monitor": result=ArmMonitor(args[3]); break;
                    case "arm-live": result=ArmLive(args[3],args.Length==5?args[4]:null); break;
                    case "network-check": result=NetworkCheck(networkConfig); break;
                    case "disable-js": JsState(true); result=JavaScriptStateDiagnostic; break;
                    case "enable-js": JsState(false); result=JavaScriptStateDiagnostic; break;
                    case "inspect-js-state": JavaScriptCheckboxState(null); result=JavaScriptStateDiagnostic; break;
                    case "reload": Chord(Dev,0x11,0x52); result=new {reloadRequested=true}; break;
                    case "show": result=new {visible=IsWindowVisible(Dev),hwnd=Dev.ToInt64()}; break;
                    default: throw new BridgeFailure("UnsupportedCommand");
                }
            }
            Result(true,null,result); return 0;
        } catch (BridgeFailure ex) {
            object diagnostic = Command == "verify" && ex.Message == "MetadataNotReturnedOrPasteBlocked"
                ? (object)new {markerFound=ProbeMarkerFound,ownMessageNodesVisited=ProbeNodesVisited} : null;
            if(ex.Message=="UnexpectedVisibleDialog") diagnostic=ModalDiagnostic;
            if(Command=="arm-live" && LiveArmDiagnostic!=null) diagnostic=LiveArmDiagnostic;
            if(ex.Message=="CannotActivateExpectedWindow"&&ActivationDiagnostic!=null)diagnostic=ActivationDiagnostic;
            if((Command=="main-inspector" || Command=="main-inspector-close") && MainInspectorMenuAttempts.Count!=0)
                diagnostic=new {menuAttempts=MainInspectorMenuAttempts.ToArray(),
                    foreground=ActivationForegroundMetadata(),mainWindow=MenuDiagnosticWindow(MainInspectorWindow),
                    inspectorNotice=InspectorNoticeDiagnostic};
            Result(false,ex.Message,diagnostic); return 2;
        }
        catch (Exception ex) { Result(false,"ProviderFailure:"+ex.GetType().Name,null); return 2; }
        finally { if(Deadline!=null)Deadline.Dispose(); if(ProcessHandle!=IntPtr.Zero)CloseHandle(ProcessHandle); }
    }
}
