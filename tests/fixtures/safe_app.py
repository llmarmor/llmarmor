"""A safely implemented chatbot application."""
import os
import openai

# LLM02 safe: key from environment
api_key = os.environ.get("OPENAI_API_KEY")

# LLM07 safe: system prompt from environment
system_prompt = os.environ.get("SYSTEM_PROMPT", "You are a helpful assistant.")

client = openai.OpenAI(api_key=api_key)

def chat(user_input):
    validated = sanitize_input(user_input)
    response = client.chat.completions.create(
        model="gpt-4",
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": validated},
        ],
        max_tokens=1000,
        timeout=30,
    )
    return response.choices[0].message.content

def sanitize_input(text):
    return text.strip()[:1000]
