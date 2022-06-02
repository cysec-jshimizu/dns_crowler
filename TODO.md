# checker.py
レコードの文法チェック
## spf
- v
- redirect
- include
## dmarc
- v
  - version
- pct
  - percentage of messages subjected to filtering
- ruf
  - reporting URI for forensic reports
- rua
  - reporting URI of aggregate reports
- p
  - policy for organization domain
- sp
  - policy for subdomains of the OD
- adkim
  - Alignment mode for DKIM
- aspf
  - Alignment mode for SPF

# main.py
- レコードの重複は無に等しい
- 最終的に各ドメインがSPF, DMARCに対応しているか，また対応しているならポリシーが厳格かどうかを取得したい
- mxドメインに対しても実行する必要がある

# domain_list.txt
- 改行区切りでdomainを羅列
