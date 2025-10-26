import jwt
import time
from flask import Flask, request, jsonify


app = Flask(__name__)

with open("jwtRS256.key", "r") as f:
    PRIVATE_KEY = f.read()


@app.route("/.well-known/oauth-authorization-server")
def metadata():
    """MCP サーバーが信頼する AS として広告するためのメタデータ"""
    return jsonify(
        {
            "issuer": "https://auth.example.com",
            "token_endpoint": "https://auth.example.com/token",
        }
    )


@app.route("/token", methods=["POST"])
def issue_token():
    """
    OAuth トークン発行エンドポイント
    Client から 'resource' と 'scope' を受け取る
    """
    data = request.json
    resource = data.get("resource")
    scope = data.get("scope")

    if not resource:
        # Clientは 'resource' を含めなければならない (MUST)
        return jsonify({"error": "resource parameter is required"}), 400

    # 本来はここで複雑な実装がある
    # 1. ユーザーの認証
    # 2. ユーザーの認可（ユーザ sub の要求した権限 scope を、その対象 resource に対して許可してよいか）

    payload = {
        "iss": "https://auth.example.com",
        "sub": "user-12345",
        "iat": int(time.time()),
        "exp": int(time.time()) + 3600,
        # RFC 8707 の核心 (MUST)
        "aud": resource,  # 1. resource 値を 'aud' (Audience) クレームに設定する
        "scope": scope,  # 2. 要求されたスコープを設定する
    }
    access_token = jwt.encode(payload, PRIVATE_KEY, algorithm="RS256")

    return jsonify(
        {"access_token": access_token, "token_type": "Bearer", "expires_in": 3600}
    )


if __name__ == "__main__":
    # 実際には HTTPS (OAuth 2.1 の要件) が必須
    app.run(port=5001, debug=True)
