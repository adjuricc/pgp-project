from gui import AppGUI
import logic
import tkinter as tk

app_gui = None

def set_status(message):
    app_gui.set_status(message)

def on_register_action(username, email, password):
    logic.register_action(username, email, password, set_status)

def on_login_action(username, email):
    logic.login_action(username, email, set_status)

def on_generate_key_pair_action(key_size):
    logic.generate_key_pair_action(key_size, set_status)

def on_keys_action():
    return logic.get_private_key_ring(set_status)

def on_public_keys_action():
    return logic.get_public_key_ring(set_status)

def on_send_message_action(filename, filepath, encryption_var, signature_var, compress_var, radix64_var, encryption_option, signature_option, enc_input, signature_input, message):
    return logic.send_message_action(filename, filepath, encryption_var, signature_var, compress_var, radix64_var, encryption_option, signature_option, enc_input, signature_input, message, set_status)

def on_export_action(username, public_key, private_key, option):
    return logic.export_keys_action(username, public_key, private_key, option)

def on_import_action(filepath):
    return logic.import_keys_action(filepath)

def on_receive_message_action():
    return logic.receive_msg_action("msg")

def main():
    global app_gui
    root = tk.Tk()

    # initialize the GUI
    app_gui = AppGUI(root)

    # set the navbar commands to the pages
    app_gui.set_navbar_commands({
        'register': app_gui.register_page,
        'login': app_gui.login_page,
        'generate_key_pair': app_gui.generate_key_pair_page,
        'keys': app_gui.keys_page,
        'send_msg': app_gui.send_message_page,
        'receive_msg': app_gui.receive_message_page,
        'import_keys': app_gui.import_keys_page,
        'export_keys': app_gui.export_keys_page
    })

    app_gui.set_footer_commands({
        'log_out': logic.log_out_action
    })

    app_gui.set_register_action(on_register_action)
    app_gui.set_login_action(on_login_action)
    app_gui.set_generate_key_pair_action(on_generate_key_pair_action)
    app_gui.set_keys_action(on_keys_action)
    app_gui.set_public_keys_action(on_public_keys_action)
    app_gui.set_send_message_action(on_send_message_action)
    app_gui.set_receive_message_action(on_receive_message_action)
    app_gui.set_export_action(on_export_action)
    app_gui.set_import_action(on_import_action)

    root.mainloop()


if __name__ == '__main__':
    main()