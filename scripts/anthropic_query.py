import sys
import os
import json
import urllib.request
import urllib.error

def query_anthropic(prompt_file):
    try:
        with open(prompt_file, 'r', encoding='utf-8', errors='replace') as f:
            prompt = f.read()
    except Exception as e:
        print(f"Error reading prompt file: {e}", file=sys.stderr)
        sys.exit(1)

    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        print("ERROR: ANTHROPIC_API_KEY environment variable is not set.", file=sys.stderr)
        sys.exit(1)

    url = "https://api.anthropic.com/v1/messages"

    system_prompt = (
        "You are a world-class DevSecOps Security Architect and Offensive Security Expert. "
        "Your task is to analyze aggregated security reports (Secrets, SAST, SCA, IaC) and source code. "
        "Identify deep logic flaws, structural vulnerabilities, and high-impact security risks. "
        "Be concise, technical, and prioritize actionable remediation. Do not engage in conversational filler."
    )

    model = os.environ.get("ANTHROPIC_MODEL", "claude-3-opus-20240229")

    payload = {
        "model": model,
        "max_tokens": 4096,
        "system": system_prompt,
        "messages": [
            {
                "role": "user",
                "content": prompt
            }
        ]
    }

    req = urllib.request.Request(url, data=json.dumps(payload).encode('utf-8'))
    req.add_header('Content-Type', 'application/json')
    req.add_header('x-api-key', api_key)
    req.add_header('anthropic-version', '2023-06-01')

    try:
        with urllib.request.urlopen(req) as response:
            response_body = response.read().decode('utf-8')
            response_json = json.loads(response_body)
            text_output = response_json.get('content', [{}])[0].get('text', '')
            print(text_output)

    except urllib.error.HTTPError as err:
        print(f"A client error occurred with Anthropic API: {err.code} - {err.reason}", file=sys.stderr)
        try:
            error_details = err.read().decode('utf-8')
            print(f"Details: {error_details}", file=sys.stderr)
        except:
            pass
        sys.exit(1)
    except Exception as e:
        print(f"An unexpected error occurred: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 anthropic_query.py <prompt_file>", file=sys.stderr)
        sys.exit(1)
    query_anthropic(sys.argv[1])
