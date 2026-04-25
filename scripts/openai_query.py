import sys
import os
import json
import urllib.request
import urllib.error

def query_openai(prompt_file):
    try:
        with open(prompt_file, 'r', encoding='utf-8', errors='replace') as f:
            prompt = f.read()
    except Exception as e:
        print(f"Error reading prompt file: {e}", file=sys.stderr)
        sys.exit(1)

    # Read API key securely from environment variables, avoiding git leaks
    api_key = os.environ.get("OPENAI_API_KEY")
    if not api_key:
        print("ERROR: OPENAI_API_KEY environment variable is not set.", file=sys.stderr)
        sys.exit(1)
        
    url = "https://api.openai.com/v1/chat/completions"
    
    # Using o3-mini (or another reasoning model) which rivals/beats Claude 4.7 Sonnet for complex security logic
    payload = {
        "model": "o3-mini",
        "messages": [
            {
                "role": "user",
                "content": (
                    "**SYSTEM PROMPT / Core Directive:**\n"
                    "You are a world-class DevSecOps Security Architect and Offensive Security Expert. "
                    "Your task is to analyze aggregated security reports (Secrets, SAST, SCA, IaC) and source code. "
                    "Identify deep logic flaws, structural vulnerabilities, and high-impact security risks. "
                    "Be concise, technical, and prioritize actionable remediation. Do not engage in conversational filler.\n\n"
                    "**USER PROMPT:**\n"
                    f"{prompt}"
                )
            }
        ]
    }

    req = urllib.request.Request(url, data=json.dumps(payload).encode('utf-8'))
    req.add_header('Content-Type', 'application/json')
    req.add_header('Authorization', f'Bearer {api_key}')

    try:
        with urllib.request.urlopen(req) as response:
            response_body = response.read().decode('utf-8')
            response_json = json.loads(response_body)
            # Extract standard OpenAI chat completion response
            text_output = response_json.get('choices', [{}])[0].get('message', {}).get('content', '')
            print(text_output)
            
    except urllib.error.HTTPError as err:
        print(f"A client error occurred with OpenAI API: {err.code} - {err.reason}", file=sys.stderr)
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
        print("Usage: python3 openai_query.py <prompt_file>", file=sys.stderr)
        sys.exit(1)
    query_openai(sys.argv[1])
