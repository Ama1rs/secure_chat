# main.py
import streamlit as st
import threading
import time
import server as server_mod
import client as client_mod
import socket

st.set_page_config(layout="wide", page_title="Secure Chat (Persistent Session)")

st.title("Secure Chat — persistent session demo")

# Sidebar controls
with st.sidebar:
    st.header("Server controls")
    host = st.text_input("Server host", value="127.0.0.1", key="host")
    port = st.number_input("Server port", value=5555, min_value=1, max_value=65535, key="port")
    if st.button("Start server"):
        server_mod.start_server(bind_host=host, bind_port=int(port))
        st.success("Server start requested")
    if st.button("Stop server"):
        server_mod.stop_server()
        st.warning("Server stop requested")

    st.markdown("---")
    st.header("Client controls")
    if "client_state" not in st.session_state:
        st.session_state.client_state = None  # dict: { "socket":..., "aes_key":..., "aes_iv":..., "priv":... }
    if st.session_state.client_state:
        st.write("Client: connected")
        if st.button("Disconnect client"):
            try:
                client_mod.close_socket(st.session_state.client_state["socket"])
            except:
                pass
            st.session_state.client_state = None
            st.warning("Client disconnected")
    else:
        st.write("Client: not connected")
        if st.button("Connect client and handshake"):
            try:
                s, k, iv, priv = client_mod.connect_and_handshake(host=host, port=int(port))
                st.session_state.client_state = {"socket": s, "aes_key": k, "aes_iv": iv, "priv": priv}
                st.success("Handshake complete — session open")
            except Exception as e:
                st.error(f"Failed to connect/handshake: {e}")

# Main area: message composer + logs
col1, col2 = st.columns([1, 1])

with col1:
    st.subheader("Send message (client)")
    message = st.text_area("Message to server", height=180, key="msg")
    if st.button("Send message"):
        if not st.session_state.client_state:
            st.error("Client not connected. Connect first.")
        else:
            try:
                client_mod.send_message(st.session_state.client_state["socket"],
                                        st.session_state.client_state["aes_key"],
                                        st.session_state.client_state["aes_iv"],
                                        message)
                st.success("Message sent")
            except Exception as e:
                st.error(f"Send failed: {e}")
                # if send failed, drop client state
                try:
                    client_mod.close_socket(st.session_state.client_state["socket"])
                except:
                    pass
                st.session_state.client_state = None

    if st.button("End session (close client)"):
        if st.session_state.client_state:
            client_mod.close_socket(st.session_state.client_state["socket"])
            st.session_state.client_state = None
            st.warning("Session ended (client closed)")

with col2:
    st.subheader("Server logs (live)")
    # small auto-refresh mechanism
    logs_text = "\n".join(server_mod.logs[-400:])
    st.code(logs_text, language=None)
    # manual refresh
    if st.button("Refresh logs"):
        st.experimental_rerun()

st.markdown("---")
st.write("Notes:")
st.write("""
- Start server first, then press 'Connect client and handshake' to open a persistent session.
- You may send multiple messages from the same session; the server will keep the AES session active until you hit 'End session (close client)' or stop the server.
- This is a demo — not production TLS. Keys and HMAC derivation are simplified for clarity.
""")

