import sys
import json
import boto3
from botocore.exceptions import ClientError

def query_bedrock(prompt_file):
    try:
        with open(prompt_file, 'r', encoding='utf-8', errors='replace') as f:
            prompt = f.read()
    except Exception as e:
        print(f"Error reading prompt file: {e}", file=sys.stderr)
        sys.exit(1)

    # Initialize the Bedrock Runtime client in the Mumbai region
    # NOTE: Ensure the EC2 instance has an IAM Role with AmazonBedrockFullAccess
    client = boto3.client('bedrock-runtime', region_name='ap-south-1')

    # Claude 4.6 Sonnet Model ID on AWS Bedrock (User Specified)
    model_id = 'global.anthropic.claude-sonnet-4-6'
    
    payload = {
        "anthropic_version": "bedrock-2023-05-31",
        "system": "You are a world-class DevSecOps Security Architect and Offensive Security Expert. Your task is to analyze aggregated security reports (Secrets, SAST, SCA, IaC) and source code. Identify deep logic flaws, structural vulnerabilities, and high-impact security risks. Be concise, technical, and prioritize actionable remediation. Do not engage in conversational filler.",
        "max_tokens": 8192,
        "temperature": 0.0, # Forced precision for security auditing
        "top_p": 1.0,
        "top_k": 250,
        "messages": [
            {
                "role": "user",
                "content": [{"type": "text", "text": prompt}]
            }
        ]
    }

    try:
        response = client.invoke_model(
            modelId=model_id,
            contentType='application/json',
            accept='application/json',
            body=json.dumps(payload)
        )
        response_body = json.loads(response.get('body').read())
        
        # Claude 3 payload structure
        text_output = response_body.get('content', [{}])[0].get('text', '')
        print(text_output)
        
    except ClientError as err:
        print(f"A client error occurred with AWS Bedrock: {err.response['Error']['Message']}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"An unexpected error occurred: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 bedrock_query.py <prompt_file>", file=sys.stderr)
        sys.exit(1)
    query_bedrock(sys.argv[1])
