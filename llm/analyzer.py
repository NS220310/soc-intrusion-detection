import openai
from llm.prompts import SYSTEM_PROMPT, build_user_prompt

openai.api_key = "YOUR_API_KEY"

def analyze_campaign(summary):
    response = openai.ChatCompletion.create(
        model="gpt-4o-mini",
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": build_user_prompt(summary)}
        ],
        temperature=0.2
    )

    return response["choices"][0]["message"]["content"]
