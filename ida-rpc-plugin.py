import ida_idaapi
import ida_kernwin
import ida_funcs
import ida_name
import ida_nalt
import time
import os

def log(msg):
    ida_kernwin.msg(f"[Discord] {msg}\n")
    print(f"[Discord] {msg}")

try:
    from pypresence import Presence
    HAS_PYPRESENCE = True
except ImportError:
    HAS_PYPRESENCE = False

class DiscordRPCPlugin(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_FIX
    comment = "Discord RPC Integration"
    help = "Discord RPC"
    wanted_name = "Discord RPC"

    def __init__(self):
        try:
            super(DiscordRPCPlugin, self).__init__()
        except:
            pass

        self.rpc = None
        self.running = False
        self.hook = None
        self.start_time = int(time.time())
        self.last_func = ""
        self.flags = ida_idaapi.PLUGIN_FIX

        log("Plugin loaded.")

    def init(self):
        log("init() started - Auto-load is active.")

        if not HAS_PYPRESENCE:
            log("Error: pypresence library not found.")
            return ida_idaapi.PLUGIN_SKIP

        self.start_rpc()

        log("Plugin is ready and in memory.")
        return ida_idaapi.PLUGIN_KEEP

    def run(self, arg):
        if self.running:
            self.stop_rpc()
        else:
            self.start_rpc()

    def term(self):
        self.stop_rpc()
        log("Closing...")

    def start_rpc(self):
        if self.running:
            log("Already loaded.")
            return
        try:
            log("Connecting to Discord...")
            self.rpc = Presence("1467007916547510457")
            self.rpc.connect()
            self.running = True

            if not self.hook:
                self.hook = IDAHooks(self)
                self.hook.hook()

            self.update_presence()
            log("Success: Connected to Discord!")
        except Exception as e:
            log(f"Connection error: {e}")
            self.running = False

    def stop_rpc(self):
        self.running = False
        if self.hook:
            self.hook.unhook()
            self.hook = None
        if self.rpc:
            try:
                self.rpc.close()
            except:
                pass
            self.rpc = None
        log("Connection lost.")

    def update_presence(self):
        if not self.running or not self.rpc:
            return
        try:
            ea = ida_kernwin.get_screen_ea()
            func = ida_funcs.get_func(ea)
            fname = ida_name.get_ea_name(func.start_ea) if func else "Idle"

            if fname != self.last_func:
                self.last_func = fname
                root = ida_nalt.get_root_filename()
                rname = os.path.basename(root) if root else "Unsaved"

                self.rpc.update(
                    details=f"File: {rname}",
                    state=f"Func: {fname}",
                    large_image="ida_logo",
                    large_text="IDA Pro 9.2",
                    start=self.start_time
                )
        except:
            pass

class IDAHooks(ida_kernwin.UI_Hooks):
    def __init__(self, plugin):
        ida_kernwin.UI_Hooks.__init__(self)
        self.plugin = plugin
        
    def screen_ea_changed(self, ea, prev_ea):
        self.plugin.update_presence()
        return 0

def PLUGIN_ENTRY():
    return DiscordRPCPlugin()
