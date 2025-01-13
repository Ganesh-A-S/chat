import streamlit as st
from groq import Groq

# Creates Groq client
client = Groq(api_key=st.secrets.get("GROQ_API_KEY"))

# Page Header
st.title("Chatbot")
st.write("Chatbot powered by Groq.")
st.divider()

# Sidebar
st.sidebar.title("Chats")

# Session State
if "default_model" not in st.session_state:
    st.session_state["default_model"] = "llama3-8b-8192"

if "messages" not in st.session_state:
    st.session_state["messages"] = []

# Display the messages
for message in st.session_state.messages:
    with st.chat_message(message["role"]):
        st.write(message["content"])

# Chat input for user message
if prompt := st.chat_input():
    # Append message to message collection
    st.session_state.messages.append({"role": "user", "content": prompt})

    # Display the new message
    with st.chat_message("user"):
        st.markdown(prompt)

    # Display the assistant response from the model
    with st.chat_message("assistant"):
        # Placeholder for the response text
        response_text = st.empty()

        # Call the Groq API
        try:
            completion = client.chat.completions.create(
                model=st.session_state.default_model,
                messages=[{"role": m["role"], "content": m["content"]} for m in st.session_state.messages],
                stream=True
            )

            full_response = ""
            for chunk in completion:
                if chunk.choices[0].delta.content:
                    full_response += chunk.choices[0].delta.content
                    response_text.markdown(full_response)

            # Add the full response to the messages
            st.session_state.messages.append({"role": "assistant", "content": full_response})

        except Exception as e:
            st.error(f"Error: {e}")
