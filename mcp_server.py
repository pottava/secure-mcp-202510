import jwt
import json
from functools import wraps
from flask import Flask, request, jsonify, g, Response


app = Flask(__name__)

MCP_SERVER_URI = "https://mcp.example.com"  # このサーバー自身の Canonical URI (MUST)

TRUSTED_ISSUER = "https://auth.example.com"  # 信頼する認証サーバーの Issuer
with open("jwtRS256.key.pub", "r") as f:  # 信頼する認証サーバーの公開鍵
    PUBLIC_KEY = f.read()

# サーバーが提供するツールの定義と、必要なスコープ
ALL_TOOLS = {
    "read_files": {
        "description": "Read files from the project.",
        "required_scope": "files:read",
    },
    "delete_files": {
        "description": "Delete files. DANGEROUS.",
        "required_scope": "files:delete",
    },
    "send_email": {
        "description": "Send an email to someone external.",
        "required_scope": "email:write",
    },
}


# --- 認証・認可デコレータ ---
def require_mcp_auth(f):
    """
    トークンを検証、aud と Scope のチェックを行う
    """

    @wraps(f)
    def decorated_function(*args, **kwargs):
        auth_header = request.headers.get("Authorization")
        if not auth_header or not auth_header.startswith("Bearer "):
            return Response(
                json.dumps({"error": "Missing or invalid Authorization header"}),
                401,
                {"WWW-Authenticate": 'Bearer realm="mcp.example.com"'},
            )
        token = auth_header.split(" ")[1]

        try:
            payload = jwt.decode(
                token,
                PUBLIC_KEY,
                algorithms=["RS256"],
                issuer=TRUSTED_ISSUER,
                audience=MCP_SERVER_URI,
            )
        except jwt.InvalidAudienceError:
            # 必須要件 1:
            # 'aud' (Audience) クレームが不一致の場合 (MUST)
            # 仕様に基づき 401 Unauthorized を返す
            return Response(
                json.dumps(
                    {
                        "error": "Invalid audience. Token is not intended for this server."
                    }
                ),
                401,
                {
                    "WWW-Authenticate": 'Bearer realm="mcp.example.com", error="invalid_token", error_description="Invalid audience"'
                },
            )
        except jwt.PyJWTError as e:
            # その他のトークンエラー（期限切れ、署名不正など）
            return Response(
                json.dumps({"error": f"Token validation failed: {e}"}),
                401,
                {
                    "WWW-Authenticate": f'Bearer realm="mcp.example.com", error="invalid_token", error_description="{e}"'
                },
            )

        # 必須要件 2:
        # 最小権限 (Scope)
        g.token_payload = payload
        g.user_scopes = payload.get("scope", "").split(" ")

        return f(*args, **kwargs)

    return decorated_function


@app.route("/.well-known/protected-resource")
def protected_resource_metadata():
    """必須要件 1 (SHOULD): 信頼する AS の広告 (RFC 9728)"""
    return jsonify(
        {
            "resource_server": MCP_SERVER_URI,
            "authorization_servers": [TRUSTED_ISSUER],
            "scopes_supported": [t["required_scope"] for t in ALL_TOOLS.values()],
        }
    )


@app.route("/tools/list", methods=["GET"])
@require_mcp_auth
def list_tools():
    """必須要件 2: 認可されたツールのみを動的にリスト"""

    # ユーザーのスコープに基づいてツールを動的にフィルタリング
    available_tools = []
    for tool_name, tool_info in ALL_TOOLS.items():
        if tool_info["required_scope"] in g.user_scopes:
            available_tools.append(
                {"name": tool_name, "description": tool_info["description"]}
            )

    return jsonify({"tools": available_tools})


@app.route("/tools/call", methods=["POST"])
@require_mcp_auth
def call_tool():
    """必須要件 3: 実行時制御 (Scope 検証、HITL、Sandbox)"""
    tool_name = request.json.get("tool_name")

    if tool_name not in ALL_TOOLS:
        return jsonify({"error": "Tool not found"}), 404

    required_scope = ALL_TOOLS[tool_name]["required_scope"]
    if required_scope not in g.user_scopes:
        # 仕様に基づき、スコープ不足は 403 Forbidden を返す (MUST)
        return (
            jsonify(
                {
                    "error": "Authorization failed. "
                    f"Missing required scope: {required_scope}"
                }
            ),
            403,
        )

    # 必須要件 3:
    # Human-in-the-Loop (HITL) (SHOULD)
    if tool_name == "delete_files":  # 信頼性が重要な操作の例
        return (
            jsonify(
                {
                    "status": "paused_for_confirmation",
                    "elicitation": {
                        "type": "confirm_delete",
                        "message": "本当にこのファイルを削除しますか？",
                        "schema": {
                            "type": "object",
                            "properties": {
                                "confirmation": {"type": "boolean", "const": True},
                                "reason": {"type": "string"},
                            },
                            "required": ["confirmation", "reason"],
                        },
                    },
                }
            ),
            200,
        )

    # 必須要件 4:
    # サンドボックス実行 (MUST)
    try:
        result = run_tool_in_sandbox(tool_name, request.json.get("params"))
        return jsonify({"status": "success", "result": result})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


def run_tool_in_sandbox(tool_name, params):
    """
    サンドボックス化されたツール実行のシミュレーション。
    (Token Passthrough の禁止 (MUST NOT) にも注意)
    """
    app.logger.info(f"SANDBOX: Executing '{tool_name}' with params {params}")

    # 実際にはここで各ツールを呼び出す
    if tool_name == "read_files":
        return "File content for 'read_files'"

    if tool_name == "send_email":
        return f"Email sent using params {params}"

    return "Unknown tool execution"


if __name__ == "__main__":
    # 実際には HTTPS (OAuth 2.1 の要件) が必須
    app.run(port=5000, debug=True)
