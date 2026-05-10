from web_access import app, socketio


if __name__ == "__main__":
    socketio.run(
        app,
        debug=False,
        host="0.0.0.0",
        port=5004,
        allow_unsafe_werkzeug=True,
    )
