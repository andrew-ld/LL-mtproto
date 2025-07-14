#!/usr/bin/env bash

set -xe

wget https://raw.githubusercontent.com/telegramdesktop/tdesktop/refs/heads/dev/Telegram/SourceFiles/mtproto/scheme/api.tl -O ll_mtproto/resources/tl/application.tl

python ll_mtproto/tl/types_generator.py --schema-file ll_mtproto/resources/tl/system.tl --output-file ll_mtproto/tl/tls_system.py
python ll_mtproto/tl/types_generator.py --schema-file ll_mtproto/resources/tl/application.tl --output-file ll_mtproto/tl/tls_application.py
