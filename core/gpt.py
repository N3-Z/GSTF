import openai
import os
import json


def generateData(payload):
    client = openai.OpenAI(api_key=os.environ.get("OPENAI_API_KEY"))
    payload_str = str(payload).replace("'", '"')
    msg = f"generate 1 indonesia data with this format {payload_str}, output just json and without message from chatgpt"

    chat = client.chat.completions.create(
        model="gpt-3.5-turbo",
        messages=[{"role": "user", "content": msg}]
    )
    return json.loads(chat.choices[0].message.content)
