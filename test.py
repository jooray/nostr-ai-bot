#!/usr/bin/env python3
import ollama
from datetime import datetime
import requests
import json

def test_ollama_connection():
    print("Testing Ollama connection...")

    # Test 1: Vérification basique de l'API
    try:
        response = requests.get("http://localhost:11434")
        print(f"API HTTP Status: {response.status_code}")
        print(f"API Response: {response.text}")
    except Exception as e:
        print(f"HTTP Request failed: {e}")
        return False

    # Test 2: Utilisation directe de l'API REST pour lister les modèles
    try:
        print("\nAttempting to list models via direct API call...")
        response = requests.get("http://localhost:11434/api/tags")
        models_data = response.json()
        print("Raw API response:", json.dumps(models_data, indent=2))

        if 'models' in models_data:
            print("\nAvailable models:")
            for model in models_data['models']:
                print(f"- {model['name']} (size: {model.get('size', 'unknown')})")
            return True
        else:
            print("Unexpected response format from Ollama API")
            return False
    except Exception as e:
        print(f"Error listing models via API: {str(e)}")
        return False

    # Test 3: Utilisation de la bibliothèque Ollama (alternative)
    try:
        print("\nAttempting to use ollama Python library...")
        client = ollama.Client(host='http://localhost:11434')
        models = client.list()
        print("Library response:", models)

        if hasattr(models, 'models'):
            print("\nAvailable models (via library):")
            for model in models.models:
                print(f"- {model.name}")
            return True
    except Exception as e:
        print(f"Error with ollama library: {str(e)}")
        return False

if __name__ == "__main__":
    if test_ollama_connection():
        print("\n✅ Ollama connection test successful!")

        # Test de conversation
        try:
            print("\nTesting chat functionality with qwen2.5 model...")
            response = ollama.chat(
                model='qwen2.5',
                messages=[{
                    'role': 'user',
                    'content': 'Bonjour! Peux-tu me dire ce que tu penses de Nostr?'
                }]
            )
            print("\nAI Response:")
            print(response['message']['content'])
        except Exception as e:
            print(f"Error during chat test: {e}")
    else:
        print("\n❌ Ollama connection test failed!")
