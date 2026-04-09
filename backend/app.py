from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import os
import json
import datetime
import uuid
from classifier import ShieldPromptClassifier

app = Flask(__name__, static_folder="../frontend", static_url_path="")
CORS(app)

classifier = ShieldPromptClassifier()

analysis_history = []


@app.route("/")
def index():
    return send_from_directory(app.static_folder, "index.html")


@app.route("/api/analyze", methods=["POST"])
def analyze():
    data = request.get_json()
    if not data or "prompt" not in data:
        return jsonify({"error": "Missing 'prompt' field"}), 400

    prompt     = data.get("prompt", "").strip()
    target_ai  = data.get("target_ai", "ChatGPT")

    if not prompt:
        return jsonify({"error": "Prompt cannot be empty"}), 400
    if len(prompt) > 5000:
        return jsonify({"error": "Prompt too long (max 5000 characters)"}), 400

    result = classifier.analyze(prompt, target_ai)

    result["recommendation"] = build_recommendation(result)

    entry = {
        "id":           str(uuid.uuid4())[:8],
        "timestamp":    datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "prompt":       prompt[:120] + ("..." if len(prompt) > 120 else ""),
        "target_ai":    target_ai,
        "score":        result["score"],
        "label":        result["label"],
        "recommendation": result["recommendation"]["action"],
    }
    analysis_history.insert(0, entry)
    if len(analysis_history) > 100:
        analysis_history.pop()

    return jsonify(result)


@app.route("/api/history", methods=["GET"])
def history():
    limit = int(request.args.get("limit", 20))
    return jsonify(analysis_history[:limit])


@app.route("/api/stats", methods=["GET"])
def stats():
    if not analysis_history:
        return jsonify({"total": 0, "safe": 0, "suspicious": 0,
                        "adversarial": 0, "flagged_rate": 0})
    total      = len(analysis_history)
    safe       = sum(1 for h in analysis_history if h["label"] == "SAFE")
    suspicious = sum(1 for h in analysis_history if h["label"] == "SUSPICIOUS")
    adversarial= sum(1 for h in analysis_history if h["label"] == "ADVERSARIAL")
    by_ai      = {}
    for h in analysis_history:
        ai = h["target_ai"]
        by_ai[ai] = by_ai.get(ai, 0) + 1
    return jsonify({
        "total":        total,
        "safe":         safe,
        "suspicious":   suspicious,
        "adversarial":  adversarial,
        "flagged_rate": round((suspicious + adversarial) / total * 100, 1),
        "by_ai":        by_ai,
    })


@app.route("/api/history", methods=["DELETE"])
def clear_history():
    analysis_history.clear()
    return jsonify({"message": "History cleared"})


def build_recommendation(result):
    score = result["score"]
    label = result["label"]
    ai    = result.get("target_ai", "the selected AI")

    if label == "SAFE":
        return {
            "action":  "SEND",
            "color":   "green",
            "title":   "Safe to send",
            "message": f"This prompt appears safe for {ai}. No adversarial patterns detected. You may proceed.",
            "steps":   [
                f"Review the prompt for clarity before sending to {ai}.",
                "Ensure your prompt aligns with the AI platform's usage policies.",
                "You're good to go — send your prompt.",
            ],
        }
    elif label == "SUSPICIOUS":
        return {
            "action":  "REVISE",
            "color":   "yellow",
            "title":   "Revision recommended",
            "message": f"This prompt contains patterns that may be flagged by {ai}'s safety filters. Consider revising before sending.",
            "steps":   [
                f"Remove or rephrase any instruction-override language (e.g., 'ignore', 'forget', 'pretend').",
                "Clarify your actual intent — state what you need directly without framing it as a role or persona override.",
                f"Re-analyze the revised prompt with ShieldPrompt before sending to {ai}.",
                "If the prompt is for legitimate research, add academic context explicitly.",
            ],
        }
    else:
        return {
            "action":  "BLOCK",
            "color":   "red",
            "title":   "Do not send",
            "message": f"This prompt is classified as adversarial. Sending it to {ai} may violate the platform's Terms of Service and could result in account suspension.",
            "steps":   [
                "Do NOT send this prompt to any AI platform.",
                f"Detected pattern: {result.get('attack_type', 'adversarial manipulation')}.",
                "If this was for security research, use an isolated, sandboxed test environment instead.",
                "Review the MITRE ATLAS technique identified and document it for your report.",
                "Consult your instructor before attempting similar test cases.",
            ],
        }


if __name__ == "__main__":
    print("=" * 55)
    print("  ShieldPrompt — IAS101 Group 1")
    print("  Starting server at http://localhost:5000")
    print("=" * 55)
    app.run(debug=True, port=5000)
