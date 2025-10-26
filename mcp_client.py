import json
import requests
import urllib3


# --- クライアント設定 ---
AUTH_SERVER_URL = "http://localhost:5001"
MCP_SERVER_API_URL = "http://localhost:5000"
MCP_SERVER_URI = "https://mcp.example.com"  # アクセスしたい MCP サーバーの URI (MUST)

# デモ用の SSL 警告を抑制
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def get_token(resource_uri, scope):
    """認証サーバーからトークンを取得する"""
    print(f"\n---> 認証サーバーにトークンを要求 (Resource: {resource_uri})")

    # 必須要件 1: 'resource' パラメータを送信する (MUST)
    response = requests.post(
        f"{AUTH_SERVER_URL}/token",
        json={"resource": resource_uri, "scope": scope},
        verify=False,  # デモ用 (SSL 検証を無効)
    )
    if response.status_code != 200:
        print(f"トークン取得失敗: {response.status_code}")
        print(response.json())
        response.raise_for_status()
    return response.json()["access_token"]


def call_mcp_api(endpoint, token, method="GET", data=None):
    """MCP サーバーの API を呼び出すヘルパー"""
    headers = {"Authorization": f"Bearer {token}"}
    url = f"{MCP_SERVER_API_URL}{endpoint}"

    if method == "GET":
        response = requests.get(url, headers=headers, verify=False)
    else:
        response = requests.post(url, headers=headers, json=data, verify=False)

    print(f"[{response.status_code}] {response.request.method} {endpoint}")
    if "WWW-Authenticate" in response.headers:
        print(f"WWW-Authenticate: {response.headers['WWW-Authenticate']}")
    print(json.dumps(response.json(), indent=2, ensure_ascii=False))
    return response


def main():
    # --- フロー 1: 正常な実行 ---
    print("--- 正常な MCP フロー ---")
    # 1. アクセスしたいMCPサーバー (mcp.example.com) を 'resource' として指定, 'email:write' は要求しない)
    mcp_token = get_token(MCP_SERVER_URI, "files:read files:delete")
    # 2. ツールリストを取得 (成功)
    call_mcp_api("/tools/list", mcp_token)
    # 3. 'send_email' を実行 (スコープ不足で 403 Forbidden)
    call_mcp_api(
        "/tools/call", mcp_token, method="POST", data={"tool_name": "send_email"}
    )

    # --- フロー 2: "Confused Deputy" 攻撃のシミュレーション ---
    print('\n\n--- "Confused Deputy" 攻撃シミュレーション ---')
    # 1. 攻撃者が、無関係な Gmail 用 (aud=gmail.com) のトークンを盗んだと仮定
    gmail_token = get_token("https://gmail.com", "email:read")
    # 2. MCPサーバーは 'aud' クレームが不一致のため、401 Unauthorized を返す (MUST)
    call_mcp_api("/tools/list", gmail_token)


if __name__ == "__main__":
    main()
