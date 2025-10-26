# セキュア MCP

[MCP の認証仕様 (2025-06-18)](https://modelcontextprotocol.io/specification/2025-06-18/basic/authorization) に準拠したサンプル Python（Flask）アプリケーション実装。

"Confused Deputy" 問題を解決するため RFC 8707 の実装に焦点を当てています。  
3 つのコンポーネントで構成されます。

1. auth_server.py: 認証サーバ (Authorization Server)。トークンを発行します。
2. mcp_server.py: MCP サーバ (Resource Server)。トークンを検証し、ツールを実行します。
3. mcp_client.py: MCP クライアント (Host)。トークンを取得し、MCP サーバを呼び出します。

## セットアップ

```bash
ssh-keygen -t rsa -b 2048 -m PEM -f jwtRS256.key -N ""
openssl rsa -in jwtRS256.key -pubout -outform PEM -out jwtRS256.key.pub
```

## サーバ起動

認証サーバ（resource パラメータを受け取り、それを aud クレームに設定した JWT を発行）をポート 5001 で起動

```bash
flask --app auth_server run -p 5001
```

MCP サーバ（aud クレームと scope クレームを厳密に検証するリソースサーバ）をポート 5000 で起動

```bash
flask --app mcp_server run -p 5000
```

## デモの実行

2 つのサーバーが起動したら、3 つ目のターミナルでクライアント スクリプトを実行します。  
このスクリプトが、推奨される利用順序と、セキュリティ攻撃のシミュレーションの両方を自動的に実行します。

```bash
python mcp_client.py
```

