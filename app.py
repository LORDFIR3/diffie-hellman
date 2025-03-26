from diffie_hellman import *
from init import *
from flask import Flask, request, jsonify, render_template, redirect, url_for
from flask_cors import CORS
import redis

app = Flask(__name__)
app.secret_key = SECRET_KEY
app.config["SESSION_TYPE"] = "redis"
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_USE_SIGNER"] = True
app.config["SESSION_KEY_PREFIX"] = "session:"
# Redis Configuration
# app.config["SESSION_REDIS"] = redis_client = redis.Redis(host=os.getenv('REDIS_HOST', 'localhost'), port=6379, db=0)
# ToDo : always check redis config, in code and in dotenv after local testing
app.config["SESSION_REDIS"] = redis_client = redis.Redis(
    host=os.getenv("REDIS_HOST", "localhost"),
    port=int(os.getenv("REDIS_PORT", 6380)),  # Azure Redis uses port 6380 for SSL
    db=1,
    password=os.getenv("REDIS_PASSWORD"),
    ssl=True,  # SSL is required for Azure Redis
    decode_responses=True  # Ensures string responses instead of bytes
)
CORS(app)


@app.route('/')
def auth():
    if not is_authenticated():
        return redirect(url_for('unauthorized'))

    return redirect(url_for('index'))

@app.route('/unauthorized')
def unauthorized():
    print(session)
    if not session.get('Authenticated'):
        return render_template('login.html')
    else:
        return redirect(url_for('index'))

@app.route('/home')
def index():
    if not session.get('Authenticated'):
        return redirect(url_for('unauthorized'))

    return render_template('index.html')


@app.route('/send_message', methods=['POST'])
def send_message():
    if not session.get('Authenticated'):
        return redirect(url_for('unauthorized'))

    data = request.json
    sender = data.get('sender')
    message = data.get('message')
    attack_mode = data.get('attackMode', False)

    if attack_mode:
        modified_message = f"{message}"
        if sender == 'Alice':
            response = (f"Mallory intercepted and forwarded to Bob;\n "
                        f"'{encrypt_message(modified_message, alice_mallory_shared)}'"
                        f" with Mallory's shared key {alice_mallory_shared}")
        else:
            response = (f"Mallory intercepted and forwarded to Alice:\n "
                        f"'{encrypt_message(modified_message,bob_mallory_shared)}'"
                        f" with Mallory's shared key {bob_mallory_shared}")
    else:
        modified_message = message
        if sender == 'Alice':
            response = (f"by Alice:\n"
                        f"'{encrypt_message(modified_message,bob_shared_key)}'"
                        f" with shared key {bob_shared_key}")
        else:
            response = (f"by Bob:\n "
                        f"'{encrypt_message(modified_message, alice_shared_key)}'"
                        f" with shared key {alice_shared_key}")

    return jsonify({
        'receivedMessage': response,
        'alicePublicKey': alice_public if not attack_mode else alice_mallory_shared,
        'bobPublicKey': bob_public if not attack_mode else bob_mallory_shared,
        'aliceSharedKey': alice_shared_key,
        'bobSharedKey': bob_shared_key,
        'malloryPublicKey': mallory_public if attack_mode else "N/A",
        'mallorySharedKey' : f"With Alice : {alice_mallory_shared}\n"
                             f"With Bob : {bob_mallory_shared}" if attack_mode else "N/A",
        'chatType': 'Under Attack' if attack_mode else 'Normal'
    })


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
