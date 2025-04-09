import requests
import time
import ssl
import os
import json
import uuid
from pynostr.event import Event, EventKind
from pynostr.relay_manager import RelayManager
from pynostr.message_type import ClientMessageType
from pynostr.key import PrivateKey
from pynostr.filters import FiltersList, Filters
from pynostr.encrypted_dm import EncryptedDirectMessage
from pynostr.utils import get_timestamp
import ollama
import gc
from datetime import datetime
import re
import concurrent.futures

# Initialize relay manager with timeout
relay_manager = RelayManager(timeout=10) # INCREASED TIMEOUT
print(f"RelayManager initialized with timeout: {relay_manager.timeout} seconds")

# Get Ollama model from environment variable
model = os.environ.get("OLLAMA_MODEL")
if not model:
    print('WARNING: The environment variable "OLLAMA_MODEL" is not set, but proceeding without AI for relay test.')
    model = None # Proceed without model
else:
    print(f"Using Ollama model: {model}")

def system_message():
    current_date = datetime.now().strftime("%A, %B %d, %Y")
    system_message = f"You are ASTROBOT. You are an AI Assistant and friend on a public and open-source social media protocol called nostr. You should always comply with the users' requests. Today is {current_date}."
    return(system_message)

def respond(message):
    if model is None:
        return "Ollama model is not configured. Cannot respond with AI."
    messages = [{"role": "system", "content": system_message()},{"role": "user", "content": message}]
    print(f"Calling Ollama for response...")

    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(ollama.chat, model=model, messages=messages)
        try:
            response_data = future.result(timeout=60) # Wait for up to 60 seconds
            response = response_data['message']['content']
            print(f"Ollama response received.")
            print(response)
            return response
        except concurrent.futures.TimeoutError:
            error_message = "ERROR: Ollama response timed out after 60 seconds."
            print(error_message)
            return error_message # Or handle timeout as you see fit (e.g., return a default response)
        except Exception as e: # Catch other potential Ollama errors
            error_message = f"ERROR: Ollama chat error: {e}"
            print(error_message)
            return error_message # Or handle other errors as needed


def run():
    messages_done = []
    print("Starting run function in TEST MODE (Relay Read Test) with PERSISTENT CONNECTIONS...")

    # Get private key from environment variable
    env_private_key = os.environ.get("PRIVATE_KEY")
    if not env_private_key:
        print('WARNING: The environment variable "PRIVATE_KEY" is not set. Generating a new one for you, set it as env var:')
        private_key = PrivateKey()
        public_key = private_key.public_key
        print(f"Generated Private key (KEEP SECRET): {private_key.bech32()}")
        print(f"Public key (shareable): {public_key.bech32()}")
        print("Exiting, please set PRIVATE_KEY environment variable with your private key to run the bot.")
        exit(1)
    else:
        print("Loading private key from environment variable.")

    private_key = PrivateKey.from_nsec(env_private_key)
    public_key = private_key.public_key
    print(f"Public key: {public_key.bech32()}")
    print(f"Public key (hex): {public_key.hex()}")

    # Read relays from env variable or use default
    env_relays = os.getenv('RELAYS')
    if env_relays is None:
        env_relays = "wss://nos.lol,wss://nostr.bitcoiner.social,wss://relay.nostr.band,wss://relay.damus.io"
    relays = env_relays.split(",")
    print(f"Relays from environment or default: {relays}")

    print("Adding relays to relay manager...")
    for relay in relays:
        print(f"Adding relay: {relay}")
        relay_manager.add_relay(relay)
    print("Relays added.")

    start_timestamp = get_timestamp()
    print(f"Starting main loop. Listening for events since timestamp: {start_timestamp}")

    filters = FiltersList([
            Filters(kinds=[EventKind.TEXT_NOTE]) # Écoute toutes les notes publiques
    ])
    subscription_id = uuid.uuid1().hex
    print(f"Creating subscription with id: {subscription_id}")
    relay_manager.add_subscription_on_all_relays(subscription_id, filters)

    # IMPORTANT: Run relay manager *once* to establish persistent connections and subscriptions
    relay_manager.run_sync()
    print("Initial relay manager sync finished. Persistent connections established.")


    while(True):
        print("--- Start of event listening cycle ---")

        while relay_manager.message_pool.has_notices():
            notice_msg = relay_manager.message_pool.get_notice()
            print(f"NOTICE from relay: {notice_msg.content}")

        print("Entering event processing loop check...")
        if relay_manager.message_pool.has_events():
            print("Message pool has events - entering loop.")
            while relay_manager.message_pool.has_events():
                event_msg = relay_manager.message_pool.get_event()
                event = event_msg.event

                if event.id in messages_done:
                    # ~ print(f"Event ID {event.id} already processed, skipping.")
                    continue

                print(f"Received event from relay: kind={event.kind}, pubkey={event.pubkey}, id={event.id}, created_at={event.created_at}")
                messages_done.append(event.id)

                if event.kind == EventKind.ENCRYPTED_DIRECT_MESSAGE:
                    print("Processing ENCRYPTED_DIRECT_MESSAGE...")
                    msg_decrypted = EncryptedDirectMessage()
                    msg_decrypted.decrypt(private_key_hex=private_key.hex(), encrypted_message=event.content, public_key_hex=event.pubkey)
                    if (len(msg_decrypted.cleartext_content) < 4):
                        print("Decrypted message too short, skipping.")
                        continue
                    print (f"Private message from {event.pubkey}: '{msg_decrypted.cleartext_content}'")
                    response = respond(msg_decrypted.cleartext_content)
                    print(f"Generated response: '{response}'")
                    print(f"Sending DM response to {event.pubkey}...")

                    dm = EncryptedDirectMessage()
                    dm.encrypt(private_key.hex(),
                        recipient_pubkey=event.pubkey,
                        cleartext_content=response,
                    )
                    dm_event = dm.to_event()
                    dm_event.sign(private_key.hex())

                    try:  # ADD TRY-EXCEPT BLOCK AROUND PUBLISH
                        print("--> Publishing DM event to relays...") # LOG BEFORE PUBLISH
                        relay_manager.publish_event(dm_event)
                        print("<-- DM event published to relays.") # LOG AFTER PUBLISH
                    except Exception as e:
                        print(f"ERROR: Exception during DM event publish: {e}") # LOG EXCEPTION

                    print(f"Response sent to {event.pubkey}.")

                elif event.kind == EventKind.TEXT_NOTE:
                    print("Processing TEXT_NOTE...")
                    print(f"Received public note from {event.pubkey}: '{event.content}'")

                    content = re.sub(r'\b(nostr:)?(nprofile|npub)[0-9a-z]+[\s]*', '', event.content)
                    if (len(content) < 4):
                        print("Public note content too short after cleaning, skipping.")
                        continue
                    print(f"Cleaned public note content: '{content}'")

                    if event.pubkey != private_key.public_key.hex(): # Only respond to others, avoid self-reply loops if we echo our own notes
                        print("Responding to public note...")
                        resp = respond(content)
                        note_event = Event(kind=EventKind.TEXT_NOTE, content=resp)

                        # Reply is Not working :
                        note_event.add_event_ref(event.id)
                        note_event.add_pubkey_ref(event.pubkey)
                        note_event.sign(private_key.hex())

                        print(f"Constructed note_event: {json.dumps(note_event.to_dict(), indent=2)}") # Log note_event JSON

                        try: # ADD TRY-EXCEPT BLOCK AROUND PUBLISH
                            print("--> Publishing public reply event to relays...") # LOG BEFORE PUBLISH
                            relay_manager.publish_event(note_event)
                            print("<-- Public reply event published to relays.") # LOG AFTER PUBLISH
                        except Exception as e:
                            print(f"ERROR: Exception during public reply event publish: {e}") # LOG EXCEPTION

                        print("Waiting for 30s before continuing...")
                        time.sleep(30)
                    else:
                        print("Ignoring public note from self.")

                else:
                    print(f"Received event of unhandled kind: {event.kind}, skipping.")

                gc.collect()
            print("Exiting event processing loop.")
        else:
            print("Message pool has no events.")
        print("Event processing finished for this cycle.")

        # ~ print("Checking relay statuses after publishing cycle:")
        # ~ for relay_url, relay in relay_manager.relays.items():
            # ~ print(f"Relay {relay_url}: Status = {relay.status}")

        # IMPORTANT: Do NOT close relay connections in the loop anymore!
        # print("Closing all relay connections...")
        # relay_manager.close_all_relay_connections()
        # print("Relay connections closed.")

        print(f"Waiting for 10 seconds before next cycle...")
        time.sleep(10)
        print("--- End of event listening cycle ---")


try:
    run()
except KeyboardInterrupt:
    print("KeyboardInterrupt detected. Exiting...")
    relay_manager.close_all_relay_connections()
    print("Relay connections closed due to KeyboardInterrupt.")
    exit(1)
except Exception as e:
    print(f"Exception occurred: {e}")
    relay_manager.close_all_relay_connections()
    print("Relay connections closed due to exception.")
    print("Restarting run function...")
    run()
