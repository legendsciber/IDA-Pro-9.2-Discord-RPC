import ida_idaapi
import ida_kernwin
import ida_funcs
import ida_name
import ida_nalt
import time
import os

def log(msg):
    ida_kernwin.msg(f"[DiscordRPC] {msg}\n")

try:
    from pypresence import Presence
    HAS_PYPRESENCE = True
except ImportError:
    log("ERROR: pypresence is not installed! Use 'pip install pypresence'.")
    HAS_PYPRESENCE = False

class DiscordRPCPlugin(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_KEEP
    comment = "Discord RPC for IDA 9.2"
    help = "Discord RPC"
    wanted_name = "Discord RPC"
    wanted_hotkey = "Ctrl-Alt-D"

    def __init__(self):
        super(DiscordRPCPlugin, self).__init__()
        self.rpc = None
        self.running = False
        self.hook = None
        self.start_time = int(time.time())
        self.last_func = ""
        log("Plugin object created.")

    def init(self):
        log("Entering init() function.")
        if not HAS_PYPRESENCE:
            return ida_idaapi.PLUGIN_SKIP

        if not self.running:
            ida_kernwin.register_timer(500, self.start_rpc)

        return ida_idaapi.PLUGIN_KEEP

    def run(self, arg=0):
        if self.running:
            self.stop_rpc()
        else:
            self.start_rpc()

    def term(self):
        self.stop_rpc()

    def start_rpc(self):
        if self.running: return -1
        try:
            client_id = "1274210451273551973"
            self.rpc = Presence(client_id)
            self.rpc.connect()
            self.running = True

            if not self.hook:
                self.hook = IDAHooks(self)
                self.hook.hook()

            self.update_presence()
            log("SUCCESS: Connected to Discord.")
        except Exception as e:
            log(f"Connection Error: {e}")
        return -1

    def stop_rpc(self):
        if self.running:
            if self.hook: self.hook.unhook()
            if self.rpc: self.rpc.close()
            self.running = False
            log("Discord connection closed.")

    def update_presence(self):
        if not self.running: return
        try:
            ea = ida_kernwin.get_screen_ea()
            func = ida_funcs.get_func(ea)
            f_name = ida_name.get_ea_name(func.start_ea) if func else "Idle"

            if f_name != self.last_func:
                self.last_func = f_name
                root_file = ida_nalt.get_root_filename()
                b_name = os.path.basename(root_file) if root_file else "No File"

                log(f"Updating: {b_name} -> {f_name}")
                self.rpc.update(
                    details=f"Analyzing: {b_name}",
                    state=f"Function: {f_name}",
                    large_image="ida_logo",
                    large_text="IDA Pro 9.2",
                    start=self.start_time
                )
        except:
            pass

class IDAHooks(ida_kernwin.UI_Hooks):
    def __init__(self, plugin):
        super(IDAHooks, self).__init__()
        self.plugin = plugin
    def screen_ea_changed(self, ea, prev_ea):
        self.plugin.update_presence()
        return 0

def PLUGIN_ENTRY():
    return DiscordRPCPlugin()

if __name__ == "__main__":
    log("Manual start detected...")

    if 'DISCORD_INST' in globals():
        try: globals()['DISCORD_INST'].term()
        except: pass

    DISCORD_INST = DiscordRPCPlugin()
    DISCORD_INST.init()

    globals()['DISCORD_INST'] = DISCORD_INST
    log("Setup complete. Check your Discord status.")