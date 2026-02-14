# synack-api

fork of [https://github.com/bamhm182/SynackAPI] but with duo support out of the box

## Installation

1. clone this repo and follow the steps mentioned in the repo to get the `response.json` and `key.pem` files

```
https://github.com/dinosn/synackDUO/tree/main
```

2. create a directory in `$HOME/.config/synack` and move the files to the folder
3. create a virtual environment and install the requirements

```
python3 -m virtualenv venv
source venv/bin/activate
pip install -r requirements.txt
```

4. run this on the first time to enter the credentials of synack platform

```python
import synack; h = synack.Handler(login=True)
h.db.discord_webhook_url = "[URL]"
```
