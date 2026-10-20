#!/bin/zsh
cd -- "$(dirname -- "$0")" || exit 1
if [[ -x ".venv/bin/python" ]]; then
  nova_python=".venv/bin/python"
elif [[ -x "/Library/Frameworks/Python.framework/Versions/3.12/bin/python3" ]]; then
  nova_python="/Library/Frameworks/Python.framework/Versions/3.12/bin/python3"
else
  nova_python="python3"
fi
if ! "$nova_python" -c "import cryptography" >/dev/null 2>&1; then
  echo "Installez les dépendances indiquées dans LISEZ-MOI.md, puis relancez Nova."
  read "?Appuyez sur Entrée pour fermer."
  exit 1
fi
"$nova_python" -m novacoin.demo --lab
read "?Appuyez sur Entrée pour fermer."
