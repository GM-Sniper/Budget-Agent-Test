import streamlit as st
import requests
import json
from google_auth_oauthlib.flow import Flow
from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request
import logging
import urllib.parse
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Get base URL from environment
BASE_URL = os.getenv("BASE_URL")

# Set up logging for debugging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Custom CSS for styling
gradient_text_html = """
<style>
@import url('https://fonts.googleapis.com/css2?family=Poppins:wght@700;900&display=swap');
.snowchat-title {
  font-family: 'Poppins', sans-serif;
  font-weight: 900;
  font-size: 4em;
  background: linear-gradient(90deg, #ff6a00, #ee0979);
  -webkit-background-clip: text;
  -webkit-text-fill-color: transparent;
  text-shadow: 2px 2px 5px rgba(0, 0, 0, 0.3);
  margin: 0;
  padding: 20px 0;
  text-align: center;
}
</style>
<div class="snowchat-title">BudgetChat</div>
"""

# Initialize session state
if "credentials" not in st.session_state:
    st.session_state["credentials"] = None
if "user_info" not in st.session_state:
    st.session_state["user_info"] = None
if "messages" not in st.session_state:
    st.session_state["messages"] = [
        {"role": "user", "content": "Hi!"},
        {"role": "assistant", "content": "Hello! I'm your budget assistant, ready to help you with your queries! 💸"},
    ]
if "assistant_response_processed" not in st.session_state:
    st.session_state["assistant_response_processed"] = True
if "history" not in st.session_state:
    st.session_state["history"] = []

# Google OAuth 2.0 configuration
SCOPES = ["openid", "https://www.googleapis.com/auth/userinfo.profile", "https://www.googleapis.com/auth/userinfo.email"]
CLIENT_SECRETS_FILE = "./client_secrets.json"
REDIRECT_URI = "http://localhost:8501"


# Function to get or refresh credentials
def get_credentials():
    creds = None
    if st.session_state["credentials"]:
        try:
            creds = Credentials.from_authorized_user_info(st.session_state["credentials"])
            if creds.expired and creds.refresh_token:
                logger.debug("Refreshing expired credentials")
                creds.refresh(Request())
                st.session_state["credentials"] = json.loads(creds.to_json())
        except Exception as e:
            logger.error(f"Error refreshing credentials: {str(e)}")
            st.session_state["credentials"] = None
    return creds

# Function to fetch user info
def get_user_info(creds):
    if not creds:
        logger.error("No credentials provided for user info fetch")
        return None
    try:
        from googleapiclient.discovery import build
        service = build("oauth2", "v2", credentials=creds)
        user_info = service.userinfo().get().execute()
        logger.debug(f"User info fetched: {user_info}")
        return user_info
    except Exception as e:
        logger.error(f"Error fetching user info: {str(e)}")
        return None

# Function to create a new session
def get_new_session_id(user_email):
    """Create a new session for the user via API and return the session ID."""
    url = f"{BASE_URL}/apps/budget_agent/users/{user_email}/sessions"
    headers = {"Content-Type": "application/json"}
    try:
        logger.debug(f"Creating session for user: {user_email}")
        response = requests.post(url, headers=headers)
        response.raise_for_status()
        session_data = response.json()
        session_id = session_data.get("id")
        if not session_id:
            logger.error("No session ID returned from API")
            return None
        logger.debug(f"Session created with ID: {session_id}")

        url = f"{BASE_URL}/run_sse"
        initial_payload = {
            "appName": "budget_agent",
            "userId": user_email,
            "sessionId": session_id,
            "newMessage": {
                "role": "model",
                "parts": [{"text": "Change user email to " + user_email}]
            },
            "streaming": False,
            "stateDelta": None
        }
        headers = {"Content-Type": "application/json"}
        try:
            logger.debug(f"[run_sse] Sending initial POST to {url} with payload: {json.dumps(initial_payload, indent=2)}")
            response = requests.post(url, json=initial_payload, headers=headers)
            logger.debug(f"[run_sse] Initial response status code: {response.status_code}")
            response.raise_for_status()
            logger.debug("[run_sse] Initial message sent successfully, proceeding with user input.")
        except requests.exceptions.RequestException as e:
            logger.error(f"[run_sse] Error sending initial message: {str(e)}")
            return f"Error sending initial message: {str(e)}"

        return session_id
    except requests.exceptions.RequestException as e:
        logger.error(f"Error creating session: {str(e)}")
        return None

# Function to display messages
def display_message(content, is_user=False):
    # User (human) on right with 👤, agent (AI) on left with 🤖
    if is_user:
        # User: right, icon on right
        html = f'<div style="text-align: right;"><span>{content}</span><span style="font-size:1.5em;vertical-align:middle;display:inline-block;margin-left:0.5em;background:#ff6a6a;padding:0.2em 0.5em;border-radius:12px;">👤</span></div>'
    else:
        # Agent: left, icon on left
        html = f'<div style="text-align: left;"><span style="font-size:1.5em;vertical-align:middle;display:inline-block;margin-right:0.5em;background:#ffd54f;padding:0.2em 0.5em;border-radius:12px;">🤖</span><span>{content}</span></div>'
    st.markdown(html, unsafe_allow_html=True)

# Function to append messages to session state
def append_message(content, role="assistant"):
    if content.strip():
        st.session_state["messages"].append({"role": role, "content": content})

# API call to cloud agent
def call_agent_api(user_input, user_id="user"):
    logger.debug("[run_sse] No session_id in session_state, attempting to create new session.")
    user_email = st.session_state.get("user_info", {}).get("email")
    logger.debug(f"[run_sse] user_email for session creation: {user_email}")
    if user_email:
        session_id = get_new_session_id(user_email)
        logger.debug(f"[run_sse] New session_id created: {session_id}")
        if session_id:
            st.session_state["session_id"] = session_id
        else:
            logger.error("[run_sse] No session ID available for agent API call after creation attempt.")
            return "Error: No session ID available"
    else:
        logger.error("[run_sse] No user email available for session creation.")
        return "Error: No user email available"
    url = f"{BASE_URL}/run_sse"
    
    payload = {
        "appName": "budget_agent",
        "userId": user_email,
        "sessionId": session_id,
        "newMessage": {
            "role": "user",
            "parts": [{"text": user_input}]
        },
        "streaming": False,
        "stateDelta": None
    }
    headers = {"Content-Type": "application/json"}
    logger.debug(f"[run_sse] Prepared payload: {json.dumps(payload, indent=2)}")
    
    try:
        logger.debug(f"[run_sse] Sending POST to {url}")
        response = requests.post(url, json=payload, headers=headers)
        logger.debug(f"[run_sse] Response status code: {response.status_code}")
        logger.debug(f"[run_sse] Response headers: {response.headers}")
        logger.debug(f"[run_sse] Response content: {response.content}")
        response.raise_for_status()
        try:
            content = response.content.decode("utf-8").strip()
            events = [e for e in content.split("\n\n") if e.strip()]
            logger.debug(f"[run_sse] Split into {len(events)} SSE events")
            reply = None
            for event in events:
                if event.startswith("data:"):
                    event = event[len("data:"):].strip()
                try:
                    api_json = json.loads(event)
                    logger.debug(f"[run_sse] Parsed JSON event: {api_json}")
                    if (
                        "content" in api_json and
                        "parts" in api_json["content"] and
                        api_json["content"]["parts"] and
                        "text" in api_json["content"]["parts"][0]
                    ):
                        reply = api_json["content"]["parts"][0]["text"]
                        logger.debug(f"[run_sse] Extracted reply from content/parts[0]/text: {reply}")
                        break
                except Exception as e:
                    logger.error(f"[run_sse] Error parsing JSON event: {str(e)} | Event: {event}")
                    continue
            if not reply:
                for event in reversed(events):
                    try:
                        if event.startswith("data:"):
                            event = event[len("data:"):].strip()
                        api_json = json.loads(event)
                        reply = api_json.get("response")
                        if reply:
                            logger.debug(f"[run_sse] Fallback reply from 'response' field: {reply}")
                            break
                    except Exception:
                        continue
            if not reply:
                reply = "No response from agent"
            logger.debug(f"[run_sse] Final API response: {reply}")
            return reply
        except Exception as e:
            logger.error(f"[run_sse] Error processing SSE response: {str(e)}")
            return f"Error: Invalid JSON response from agent: {str(e)}"
    except requests.exceptions.RequestException as e:
        logger.error(f"[run_sse] Error calling agent: {str(e)}")
        return f"Error calling agent: {str(e)}"

# Main app logic
st.markdown(gradient_text_html, unsafe_allow_html=True)

# Check for OAuth redirect parameters
query_params = st.query_params
auth_code = query_params.get("code", None)
state = query_params.get("state", None)

# OAuth flow
if not st.session_state["credentials"]:
    if auth_code and state:
        try:
            logger.debug(f"Processing OAuth redirect with code: {auth_code}, state: {state}")
            flow = Flow.from_client_secrets_file(
                CLIENT_SECRETS_FILE,
                scopes=SCOPES,
                redirect_uri=REDIRECT_URI
            )
            flow.fetch_token(code=auth_code)
            creds = flow.credentials
            if creds:
                logger.debug("Credentials obtained successfully")
                st.session_state["credentials"] = json.loads(creds.to_json())
                st.session_state["user_info"] = get_user_info(creds)
                if st.session_state["user_info"]:
                    user_email = st.session_state["user_info"].get("email")
                    session_id = get_new_session_id(user_email)
                    if session_id:
                        st.session_state["session_id"] = session_id
                    else:
                        logger.error("Failed to create session after login")
                        st.error("Failed to create session after authentication.")
                    st.query_params.clear()
                    st.rerun()
                else:
                    st.error("Failed to retrieve user information after authentication.")
                    st.session_state["credentials"] = None
            else:
                st.error("Authentication failed. Please try again.")
                st.session_state["credentials"] = None
        except Exception as e:
            logger.error(f"Error processing OAuth redirect: {str(e)}")
            st.error(f"Error during authentication: {str(e)}")
            st.session_state["credentials"] = None
    else:
        try:
            logger.debug("Starting OAuth flow")
            flow = Flow.from_client_secrets_file(
                CLIENT_SECRETS_FILE,
                scopes=SCOPES,
                redirect_uri=REDIRECT_URI
            )
            auth_url, state = flow.authorization_url(
                access_type="offline",
                include_granted_scopes="true",
                prompt="consent"
            )
            logger.debug(f"Redirecting to Google auth URL: {auth_url}")
            login_button_html = f'''
                <div style="display: flex; justify-content: center; align-items: center; margin: 2em 0;">
                    <a href="{auth_url}" target="_self" style="text-decoration: none;">
                        <button style="font-weight: bold; font-size: 1.2em; padding: 0.75em 2em; border-radius: 8px; background: linear-gradient(90deg, #ff6a00, #ee0979); color: white; border: none; cursor: pointer;">Login with Google</button>
                    </a>
                </div>
            '''
            st.markdown(login_button_html, unsafe_allow_html=True)
        except Exception as e:
            logger.error(f"Error generating auth URL: {str(e)}")
            st.error(f"Error initiating authentication: {str(e)}")
else:
    # Logged-in state: Verify credentials and show chat interface
    creds = get_credentials()
    if not creds:
        logger.error("Invalid credentials detected")
        st.error("Invalid credentials. Please log in again.")
        st.session_state["credentials"] = None
        st.session_state["user_info"] = None
        st.rerun()
    elif not st.session_state["user_info"]:
        logger.debug("Fetching user info for logged-in user")
        st.session_state["user_info"] = get_user_info(creds)
        if not st.session_state["user_info"]:
            logger.error("User info not available after login")
            st.error("Failed to retrieve user information. Please log in again.")
            st.session_state["credentials"] = None
            st.session_state["user_info"] = None
            st.rerun()
    else:
        # Sidebar with reset and logout
        st.sidebar.write(f"Logged in as: {st.session_state['user_info'].get('email', 'Unknown')}")
        if st.sidebar.button("Logout"):
            logger.debug("User initiated logout")
            st.session_state["credentials"] = None
            st.session_state["user_info"] = None
            st.session_state["messages"] = [
                {"role": "user", "content": "Hi!"},
                {"role": "assistant", "content": "Hello! I'm your budget assistant, ready to help you with your queries! 💸"},
            ]
            st.session_state["history"] = []
            st.rerun()

        if st.sidebar.button("Reset Chat"):
            logger.debug("User initiated chat reset")
            st.session_state["messages"] = [
                {"role": "user", "content": "Hi!"},
                {"role": "assistant", "content": "Hello! I'm your budget assistant, ready to help you with your queries! 💸"},
            ]
            st.session_state["history"] = []
            st.rerun()

        logger.debug("Rendering chat interface")
        # Display chat history
        for message in st.session_state["messages"]:
            display_message(message["content"], is_user=(message["role"] == "user"))

        # Handle user input
        if prompt := st.chat_input("Type your message..."):
            if len(prompt) > 500:
                st.error("Input is too long! Please limit your message to 500 characters.")
            else:
                logger.debug(f"User input received: {prompt}")
                append_message(prompt, role="user")
                st.session_state["assistant_response_processed"] = False
                display_message(prompt, is_user=True)

        # Process assistant response
        if (
            st.session_state["messages"]
            and st.session_state["messages"][-1]["role"] == "user"
            and not st.session_state["assistant_response_processed"]
        ):
            user_input = st.session_state["messages"][-1]["content"]
            user_id = st.session_state["user_info"].get("email", "user")
            with st.spinner("Thinking..."):
                response = call_agent_api(user_input, user_id=user_id)
                append_message(response)
                st.session_state["assistant_response_processed"] = True
                display_message(response)
                