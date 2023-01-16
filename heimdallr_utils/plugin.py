
# IDA imports
import ida_idaapi
import ida_kernwin
import ida_hexrays
import ida_nalt
import ida_registry
import idautils
import ida_lines
import idc

# Version handling for clipboard access
major, minor = map(int, ida_kernwin.get_kernel_version().split("."))
using_ida7api = (major > 6)
using_pyqt5 = using_ida7api or (major == 6 and minor >= 9)
if using_pyqt5:
    from PyQt5.Qt import QApplication
else:
    from PySide.QtGui import QApplication

# RPC import
import grpc
import heimdallr_grpc.heimdallr_pb2 as heimdallr_pb2
import heimdallr_grpc.heimdallr_pb2_grpc as heimdallr_pb2_grpc
from concurrent import futures

from typing import NamedTuple, List, Optional
import os, socket
import json
import platform
import itertools
import time
from threading import Lock
from urllib.parse import quote as url_quote
from pathlib import Path


# Constants
VERSION = "0.4.0"
port_base = 40000
port_max =  65535
offset_step = 1009
history_size = 60

# Per Platform Global Paths
heimdallr_path = None
idauser_path = None

def set_global_paths() -> None:
    """Sets the appropriate global IDA User and Heimdallr config paths"""
    global heimdallr_path, idauser_path
    
    if platform.system() == "Windows":
        idauser_path = Path(os.path.expandvars("%APPDATA%/Hex-Rays/IDA Pro/"))
        heimdallr_path = Path(os.path.expandvars("%APPDATA%/heimdallr/"))
    else:
        idauser_path = Path(os.path.expandvars("$HOME/.idapro/"))
        heimdallr_path = Path(os.path.expandvars("$HOME/.config/heimdallr/"))
    if not heimdallr_path.exists():
        heimdallr_path.mkdir(parents = True)
        


class rpcHandle(NamedTuple):
    """Helper class for storing RPC endpoint information"""
    pid: int
    address: str
    file_name: str
    file_hash: str

# Mutex for ida_thread_sync
mutex = Lock()

# https://github.com/pwndbg/pwndbg/blob/612328a0a7d5d4e787529539735a415456f326c5/ida_script.py#L58
def ida_thread_sync(f):
    """Function decorator: around a function that requires access to the IDA main thread.
    This is anything that requires anything to do with the database or GUI.
    
    Due to the RPC server running in a seperate thread this is required for most functions.
    """
    def wrapper(*a, **kw):
        rv = []
        error = []

        def work():
            try:
                result = f(*a, **kw)
                rv.append(result)
            except Exception as e:
                error.append(e)
            return 0
        
        # Protects rv & error
        with mutex:
            flags = ida_kernwin.MFF_FAST
            ida_kernwin.execute_sync(work, flags)

        if error:
            msg = "Failed on calling {}.{} with args: {}, kwargs: {}\nException: {}".format(
                f.__module__, f.__name__, a, kw, str(error[0])
            )
            print("[!!!] ERROR:", msg)
            raise error[0]

        return rv[0]

    return wrapper

def focus_window():
    """Brings the IDA window to the foreground using QTWidgets.
    """
    # https://www.riverbankcomputing.com/static/Docs/PyQt5/
    qtwidget = ida_kernwin.PluginForm.TWidgetToPyQtWidget(ida_kernwin.get_current_viewer())
    window = qtwidget.window()
    
    # UnMinimize
    WindowMinimized =  0x00000001 # https://www.riverbankcomputing.com/static/Docs/PyQt5/api/qtcore/qt.html#WindowState
    cur_state = window.windowState()
    new_state = cur_state & (~WindowMinimized)
    window.setWindowState(new_state)
    
    # Switch desktop / give keyboard control
    window.show() 
    window.raise_() # Bring to front (MacOS)
    window.activateWindow() # Bring to front (Windows)

def activate_window(name : str) -> bool:
    """Brings a IDA window with name `name` to the foreground.


    Args:
    - name - name of IDA tab to bring to front


    Returns:
    False if window was not found
    """
    target_view = ida_kernwin.find_widget(name)
    if not target_view:
        return False
    ida_kernwin.activate_widget(target_view, True)
    return True

@ida_thread_sync
def bring_to_front():
    """Brings IDA into focus"""
    focus_window()

@ida_thread_sync
def goto(addr : int):
    """Goto to position addr

    Args:
    - addr - address to goto
    """
    ida_kernwin.jumpto(addr)

@ida_thread_sync
def is_view_type(type):
    """Checks if the current view is of ta given type

    Args:
    - type - name of idb being searched for - i.e. ida_kernwin.BWN_DISASM

    Returns:
    True if type matched
    False if not
    """
    view = ida_kernwin.get_current_viewer()
    if ida_kernwin.get_widget_type(view) == type:
        return True
    return False

@ida_thread_sync
def switch_to_diasm():
    """Switches to the diassembly view. Opens a new one if not found."""
    if not activate_window("IDA View-A"):
        ida_kernwin.open_disasm_window("IDA View-A")

@ida_thread_sync
def switch_to_pseudo(addr : int):
    """Switches to the decompiler view. Opens a new one if not found.
    Args:
    - addr - address to decompile when opening new decompiler view
    """

    if not activate_window("Pseudocode-A"):
        ida_hexrays.open_pseudocode(addr, ida_hexrays.OPF_REUSE)



"""
Main thread seems to need time to execute the GUI actions
"""
def goto_disasm(addr : int):
    """Implementation of idaRPC.disasmGoTo"""
    bring_to_front()
    if not is_view_type(ida_kernwin.BWN_DISASM):
        time.sleep(0.25) # Allows window to be active - otherwise sleep doesn't work
        switch_to_diasm()
    goto(addr)

def goto_psudo(addr : int):
    """Implementation of idaRPC.pseudoGoTo"""
    bring_to_front()
    if not is_view_type(ida_kernwin.BWN_PSEUDOCODE):
        time.sleep(0.25) # Allows window to be active - otherwise sleep doesn't work
        switch_to_pseudo(addr)
    goto(addr)

def goto_generic(addr : int):
    """Implementation of idaRPC.genericgoTo"""

    bring_to_front()
    goto(addr)

def copy_to_clip(data):
    """Copes `data` to clipboard

    Args:
    - data - data to be added to clipboard
    """
    QApplication.clipboard().setText(data)
    print("Copied to clipboard!")

def copy_link():
    """
    Implementation of heimdallr:link shortcut
    Generates a link to the current IDA cursor position
    Copies result onto the clipboard
    """
    addr = idc.get_screen_ea()
    view_str = get_current_view_str()
    link = create_link(addr, view_str)
    copy_to_clip(link)


def get_current_view_str():
    """Gets the view_str for the current viewer"""
    view = ida_kernwin.get_current_viewer()
    view_type = ida_kernwin.get_widget_type(view)

    if view_type == ida_kernwin.BWN_PSEUDOCODE:
        return "pseudo"
    elif view_type == ida_kernwin.BWN_DISASM:
        return "disasm"
    else:
        raise RuntimeError("Current view unsupported for links")

def create_link(addr : int, view_str : Optional[str] = None) -> str:
    """Creates a link to the `addr` in view `view_str`

    Args:
    - addr - address to link to 
    - view_str - view type to link to - usually "psuedo" or "disasm". Created by `get_current_view_str()`

    Returns:
    String containing URI for `address` and `view_str` in the current IDB
    """
    file_name = Path(idc.get_idb_path()).name
    file_hash : bytes  = ida_nalt.retrieve_input_file_md5().hex()
    
    uri = f"ida://{url_quote(file_name)}?offset={hex(addr)}&hash={file_hash}"
    if view_str:
        uri += f"&view={view_str}"
    
    return uri

def copy_note():
    """
    Implementation of heimdallr:note shortcut
    Generates a note for the selected text in Psuedocode or Disassembly View
    Copies result onto the clipboard
    """
    file_name = Path(idc.get_idb_path()).name
    file_hash : bytes  = ida_nalt.retrieve_input_file_md5().hex()
    note = ""

    t0, t1, view = ida_kernwin.twinpos_t(), ida_kernwin.twinpos_t(), ida_kernwin.get_current_viewer()
    if not ida_kernwin.read_selection(view, t0, t1):
        raise RuntimeError("Could not read selection")

    view_type = ida_kernwin.get_widget_type(view)
    start, end = t0.place(view).toea(), t1.place(view).toea()
    size = end - start + 1
    note += "```\n"
    if view_type == ida_kernwin.BWN_PSEUDOCODE:
        # Get selected line numbers within the psuedo code
        start_lnm = t0.place_as_simpleline_place_t().n
        end_lnm = t1.place_as_simpleline_place_t().n
        # Extract those from the decompilation
        print(f"pseudo @ {start} {start_lnm + 1}:{end_lnm + 1}")
        psudo_text = str(ida_hexrays.decompile(start)).split("\n")
        note += '\n'.join(psudo_text[start_lnm: end_lnm + 1])
    elif view_type == ida_kernwin.BWN_DISASM:
        print(f"disasm cpy (new) {hex(start)}, {hex(end)}")
        disasm = []
        for ea in idautils.Heads(start, end + 1):
            lines: List[str] = None
            best, lines = ida_lines.generate_disassembly(ea, 64, 4, True)
            try:
                disasm.append(lines[best])
            except IndexError:
                pass
        note += '\n'.join(disasm)
    else:
        raise RuntimeError("Current view unsupported for notes")
    note += "\n```\n"
    link = f"{file_name}:{hex(start)}"
    view_str = get_current_view_str()
    note += f"[{link}]({create_link(start, view_str)})"
    copy_to_clip(note)

actions = [
    {
        'id': 'heimdallr:note',
        'name': 'Copy note to clipboard',
        'hotkey': 'Ctrl+Shift+N',
        'comment': 'Generate a code block of the current selection and copy it to the clipboard',
        'callback': copy_note,
        'menu_location': 'Edit/Make Note'
    },
    {
        'id': 'heimdallr:link',
        'name': 'Copy link to clipboard',
        'hotkey': 'Ctrl+Alt+N',
        'comment': 'Generate a link to the current cursor and copy it to the clipboard',
        'callback': copy_link,
        'menu_location': 'Edit/Make Linkk'
    },
]


class ActionHandler(ida_kernwin.action_handler_t):
    """Genetric ActionHandler class to create shortcuts in IDA"""
    def __init__(self, callback):
        
        ida_kernwin.action_handler_t.__init__(self)
        self.callback = callback
    
    def activate(self, ctx):

        self.callback()
        return 1

    def update(self, ctx):
        
        return ida_kernwin.AST_ENABLE_ALWAYS

def register_actions():
    """Registers shortcuts defined in the `actions` array"""
    for action in actions:

        if not ida_kernwin.register_action(ida_kernwin.action_desc_t(
            action['id'], # Must be the unique item
            action['name'], # The name the user sees
            ActionHandler(action['callback']), # The function to call
            action['hotkey'], # A shortcut, if any (optional)
            action['comment'] # A comment, if any (optional)
        )):

            print('Failed to register ' + action['id'])

        if not ida_kernwin.attach_action_to_menu(
            action['menu_location'], # The menu location
            action['id'], # The unique function ID
            0):

            print('Failed to attach to menu '+ action['id'])

# RPC Server Class
class idaRPC(heimdallr_pb2_grpc.idaRPC):
    """Implements the idaRPC protocol from heimdallr-grpc"""
    def disasmGoTo (
            self, request: heimdallr_pb2.GoToRequest,
            context: grpc.ServicerContext) -> heimdallr_pb2.ResponseCode:
        print(f"[Heimdallr RPC] GoTo Disassembly request {request.address} size {request.size}")
        # goto_disasm(int(request.address, 16)) # Currently borked as can't activate windowcat
        goto_disasm(int(request.address, 16))

        return heimdallr_pb2.ResponseCode(Response=heimdallr_pb2.Resp_Success)
    def pseudoGoTo(
            self, request: heimdallr_pb2.GoToRequest,
            context: grpc.ServicerContext) -> heimdallr_pb2.ResponseCode:
        print(f"[Heimdallr RPC] GoTo Pseudocode request  {request.address} size {request.size}")
        goto_psudo(int(request.address, 16))
        return heimdallr_pb2.ResponseCode(Response=heimdallr_pb2.Resp_Success)
    
    def genericGoTo(
            self, request: heimdallr_pb2.GoToRequest,
            context: grpc.ServicerContext) -> heimdallr_pb2.ResponseCode:
        print(f"[Heimdallr RPC] GoTo request  {request.address} size {request.size}")
        goto_generic(int(request.address, 16))
        return heimdallr_pb2.ResponseCode(Response=heimdallr_pb2.Resp_Success)

def port_available(port_no) -> bool:
    """Identifies if a port is free by attempting to bind to it
    
    Args:
    - port_no to test
    
    Returns:
    If port was free
    """

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.bind(("127.0.0.1", port_no))
            return True
        except socket.error as e:
            return False

def generate_rpc_handle() -> rpcHandle:
    """Generates a rpcHandle for the current process containing an available port
    
    Returns:
    rpcHandle object containing information"""
    pid = os.getpid()
    
    # Get open port for RPC client
    available = False
    offset = 0
    while not available:
        port = port_base + ((pid + offset) % (port_max - port_base))
        available = port_available(port)
        if not available:
            offset += offset_step
    file_name = Path(idc.get_idb_path()).name
    file_hash : bytes  = ida_nalt.retrieve_input_file_md5() 

    return rpcHandle(pid, f"127.0.0.1:{port}", file_name, file_hash.hex())
    
def write_handle(handle : rpcHandle) -> Path:
    """Writes an rpcHandle object to the rpc_endpoints directory
    
    Allows heimdallr to search currently open IDA instancs"""
    global heimdallr_path

    data = json.dumps(handle._asdict())
    rpc_dir = heimdallr_path / "rpc_endpoints"

    rpc_dir.mkdir(parents = True, exist_ok = True)
    endpoint_path = rpc_dir / f"{handle.pid}"
    with open(endpoint_path, "w") as fd:
        fd.write(data)
    print(f"Wrote {data} to {endpoint_path}")
    return endpoint_path

def update_history() -> None:
    """Updates the history.json file from IDAs internal registry. Required for cross platform access to IDAs weird
    windows registry format without opening IDA."""
    global idauser_path
    # get current history json
    
    # check lock
    lock_path = idauser_path / "history.lock"

    if lock_path.exists():
        rel = time.time() - lock_path.stat().st_atime
        print(f"Lock exists on history file, unable to update {lock_path}, age {rel}s")
        if rel < (60 * 60):
            return
        # Deletes after 1 hour - lock should only be held for a few seconds 
        print(f"Lock is old, removing")
        lock_path.unlink()
    
    lock_path.touch()
    
    history_path = idauser_path / "history.json"
    local_history = []
    if history_path.exists():
        with open(history_path, "r") as fd:
            local_history = json.load(fd)

    # get ida history

    history = ida_registry.reg_read_strlist("History")
    history64 = ida_registry.reg_read_strlist("History64")
    
    # Interleaves the history files. Ensures they can't just keep each other out
    combined = [x for x in itertools.chain(*itertools.zip_longest(history, history64)) if x is not None]

    # remove existing items
    if len(local_history) > 0:
        for item in combined:
            if item in local_history:
                local_history.remove(item)
    
    # prepend new items to front
    local_history = combined + local_history
    if len(local_history) > history_size:
        local_history[:history_size]

    # write new history json
    with open(history_path, "w") as fd:
        json.dump(local_history, fd)
    
    # Release lock
    lock_path.unlink()


class heimdallrRPC(ida_idaapi.plugin_t):
    def __init__(self):
        self.flags = ida_idaapi.PLUGIN_KEEP
        self.comment = "RPC plugin to allow Heimdallr URIs to function"
        self.help = "heimdallrRPC"
        self.wanted_name = "heimdallrRPC"
        self.wanted_hotkey = ""
        self.rpc_server = None
        self.handle = None
        self.handle_path = None      
        self.thread_pool = None  

    def setup_rpc(self) -> grpc.server:
        self.handle = generate_rpc_handle()
        self.thread_pool = futures.ThreadPoolExecutor(max_workers=2)
        self.rpc_server = grpc.server(self.thread_pool)

        heimdallr_pb2_grpc.add_idaRPCServicer_to_server(idaRPC(), self.rpc_server)
        self.rpc_server.add_insecure_port(self.handle.address)
        print(f"Starting server on {self.handle.address}")
        self.rpc_server.start()
        self.handle_path = write_handle(self.handle)
  
    def init(self):
        # ToDo: Detect Headless and do not register plugin
        set_global_paths()
        if self.rpc_server is None:
            print("[Heimdallr RPC] Plugin version {}".format(VERSION))
            self.setup_rpc()
            update_history()
            register_actions()
        return ida_idaapi.PLUGIN_KEEP

    def run(self, args):
        pass

    def term(self):
        if self.rpc_server:
            self.rpc_server.stop(grace=None)
        if self.handle_path:
            self.handle_path.unlink(missing_ok=True)
        if self.thread_pool:
            self.thread_pool.shutdown(wait = False, cancel_futures = True)
        self.flags = ida_idaapi.PLUGIN_UNL
    
