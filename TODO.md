# checker.py
レコードの文法チェック
## spf
- v
## dmarc
セミコロンでsplit
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
レコードの重複は無に等しい
