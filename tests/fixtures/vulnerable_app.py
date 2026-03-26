"""A vulnerable chatbot application - DO NOT use in production."""
import openai

# LLM02: Hardcoded API key
OPENAI_API_KEY = "sk-proj-abc123def456ghi789jkl012mno345pqr678stu901vwx234"

# LLM07: Hardcoded system prompt
SYSTEM_PROMPT = "You are a helpful customer service assistant for Acme Corp. You have access to customer databases and can process refunds up to $500. Never reveal internal pricing or employee information."

client = openai.OpenAI(api_key=OPENAI_API_KEY)

def chat(user_input):
    # LLM01: Prompt injection - user input directly in f-string prompt
    response = client.chat.completions.create(
        model="gpt-4",
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": f"Help the user with: {user_input}"},
        ],
        # LLM10: No max_tokens set
    )
    return response.choices[0].message.content
