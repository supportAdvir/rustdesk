#!/usr/bin/env python3
"""Políticas assinadas das apps (custom.txt) para o fork do RustDesk.

O cliente RustDesk (src/common.rs::read_custom_client, v1.5.3) lê `custom.txt` da
pasta do executável, faz base64-decode, verifica uma assinatura Ed25519 no formato
"combined" do libsodium (assinatura(64) || mensagem) com a chave pública fixa
`KEY` e aplica o JSON: `app-name`, `default-settings`, `override-settings` e as
restantes chaves de topo como HARD_SETTINGS (conn-type, disable-installation...).

Upstream, `KEY` é a chave da RustDesk: só eles assinam. No nosso fork trocamos
`KEY` pela nossa chave de políticas (separada da chave do servidor) e assinamos aqui.

Subcomandos:
  genkey      gera a chave privada de políticas (PEM) e mostra a pública
  patch-fork  troca a KEY oficial pela nossa em <fork>/src/common.rs
  build       settings-*.json + variáveis de ambiente -> custom.txt assinado
  verify      verifica e mostra um custom.txt (como o cliente faria)

Só usa a biblioteca padrão e o executável `openssl` (3.x).
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

OFFICIAL_KEY = "5Qbwsde3unUcJBtrx9ZkvUmwFNoExHzpryHuPUdqlWM="
KEY_LINE = re.compile(r'(const KEY: &str = ")([A-Za-z0-9+/=]{44})(";)')
COMMON_RS = Path("src") / "common.rs"

SIG_LEN = 64
RAW_KEY_LEN = 32
# Prefixo DER (SubjectPublicKeyInfo) de uma chave pública Ed25519; seguem-se 32 bytes.
ED25519_SPKI_PREFIX = bytes.fromhex("302a300506032b6570032100")

# Marcadores nos settings-*.json -> variável de ambiente com o valor real.
PLACEHOLDERS = {
    "<RENDEZVOUS_SERVER>": "RENDEZVOUS_SERVER",
    "<API_SERVER>": "API_SERVER",
    "<RS_PUB_KEY>": "RS_PUB_KEY",
}
NESTED_SECTIONS = ("default-settings", "override-settings")


class PolicyError(Exception):
    """Erro de configuração/assinatura com mensagem para o operador."""


# --------------------------------------------------------------------- openssl
def _openssl(*args: str, data: bytes | None = None) -> bytes:
    try:
        res = subprocess.run(["openssl", *args], input=data, capture_output=True, check=False)
    except FileNotFoundError as exc:
        raise PolicyError("openssl não encontrado no PATH") from exc
    if res.returncode != 0:
        raise PolicyError(f"openssl {args[0]} falhou: {res.stderr.decode(errors='replace').strip()}")
    return res.stdout


def raw_public_key(pem_path: Path) -> bytes:
    der = _openssl("pkey", "-in", str(pem_path), "-pubout", "-outform", "DER")
    if len(der) != len(ED25519_SPKI_PREFIX) + RAW_KEY_LEN or not der.startswith(ED25519_SPKI_PREFIX):
        raise PolicyError(f"{pem_path} não é uma chave privada Ed25519")
    return der[-RAW_KEY_LEN:]


def sign(message: bytes, pem_path: Path) -> bytes:
    with tempfile.TemporaryDirectory() as tmp:
        msg = Path(tmp) / "msg.bin"
        msg.write_bytes(message)
        sig = _openssl("pkeyutl", "-sign", "-inkey", str(pem_path), "-rawin", "-in", str(msg))
    if len(sig) != SIG_LEN:
        raise PolicyError(f"assinatura com {len(sig)} bytes (esperado {SIG_LEN})")
    return sig


def verify_signature(message: bytes, signature: bytes, raw_pub: bytes) -> bool:
    with tempfile.TemporaryDirectory() as tmp:
        pub = Path(tmp) / "pub.der"
        pub.write_bytes(ED25519_SPKI_PREFIX + raw_pub)
        msg = Path(tmp) / "msg.bin"
        msg.write_bytes(message)
        sig = Path(tmp) / "sig.bin"
        sig.write_bytes(signature)
        res = subprocess.run(
            ["openssl", "pkeyutl", "-verify", "-pubin", "-keyform", "DER", "-inkey", str(pub),
             "-rawin", "-in", str(msg), "-sigfile", str(sig)],
            capture_output=True, check=False,
        )
    return res.returncode == 0


def decode_pubkey(b64: str) -> bytes:
    try:
        raw = base64.b64decode(b64.strip(), validate=True)
    except ValueError as exc:
        raise PolicyError("chave pública não é base64 válido") from exc
    if len(raw) != RAW_KEY_LEN:
        raise PolicyError(f"chave pública com {len(raw)} bytes (esperado {RAW_KEY_LEN})")
    return raw


# --------------------------------------------------------------------- settings
def _substitute(value: str, env: dict[str, str]) -> str:
    for marker, var in PLACEHOLDERS.items():
        if marker in value:
            real = env.get(var, "").strip()
            if not real:
                raise PolicyError(f"falta a variável de ambiente {var} (usada por {marker})")
            value = value.replace(marker, real)
    if re.search(r"<[A-Z_]+>", value):
        raise PolicyError(f"marcador desconhecido por substituir: {value}")
    return value


def _check_flat(section: str, obj: dict, env: dict[str, str]) -> dict[str, str]:
    out: dict[str, str] = {}
    for key, value in obj.items():
        if not isinstance(value, str):
            # O cliente ignora em silêncio valores que não sejam texto (v.as_str()).
            raise PolicyError(f'{section}.{key}: o valor tem de ser texto ("Y"/"N"...), não {value!r}')
        out[key] = _substitute(value, env)
    return out


def render_settings(settings: dict, env: dict[str, str]) -> dict:
    """Remove comentários (chaves "_..."), substitui marcadores e valida tipos."""
    if not isinstance(settings, dict):
        raise PolicyError("o ficheiro de políticas tem de ser um objeto JSON")
    out: dict = {}
    for key, value in settings.items():
        if key.startswith("_"):
            continue
        if key in NESTED_SECTIONS:
            if not isinstance(value, dict):
                raise PolicyError(f"{key} tem de ser um objeto")
            out[key] = _check_flat(key, value, env)
        else:
            out.update(_check_flat("(topo)", {key: value}, env))
    override = out.get("override-settings", {})
    if bool(override.get("custom-rendezvous-server")) != bool(override.get("key")):
        raise PolicyError("override-settings: o host e a chave têm de ir sempre juntos")
    if override.get("key"):
        decode_pubkey(override["key"])
    return out


def build_custom_txt(settings: dict, pem_path: Path, env: dict[str, str]) -> str:
    message = json.dumps(render_settings(settings, env), ensure_ascii=False,
                         separators=(",", ":")).encode("utf-8")
    return base64.b64encode(sign(message, pem_path) + message).decode("ascii")


def read_custom_txt(text: str, raw_pub: bytes) -> dict:
    """Mesmos passos que read_custom_client: decode64 -> verify -> JSON."""
    try:
        data = base64.b64decode(text.strip(), validate=True)
    except ValueError as exc:
        raise PolicyError("custom.txt não é base64 válido") from exc
    if len(data) <= SIG_LEN:
        raise PolicyError("custom.txt demasiado curto")
    signature, message = data[:SIG_LEN], data[SIG_LEN:]
    if not verify_signature(message, signature, raw_pub):
        raise PolicyError("assinatura inválida (chave errada ou ficheiro alterado)")
    return json.loads(message)


# --------------------------------------------------------------------- fork
def patch_fork(fork_dir: Path, policy_pub_b64: str) -> str:
    decode_pubkey(policy_pub_b64)
    path = fork_dir / COMMON_RS
    src = path.read_text(encoding="utf-8")
    matches = KEY_LINE.findall(src)
    if len(matches) != 1:
        raise PolicyError(f"esperava 1 'const KEY' em {path}, encontrei {len(matches)}: o upstream mudou?")
    current = matches[0][1]
    if current == policy_pub_b64:
        return "já estava aplicado"
    if current != OFFICIAL_KEY:
        raise PolicyError(f"KEY em {path} não é a oficial nem a nossa ({current}); não altero")
    path.write_text(KEY_LINE.sub(rf"\g<1>{policy_pub_b64}\g<3>", src), encoding="utf-8", newline="\n")
    return "KEY substituída"


# --------------------------------------------------------------------- CLI
def _signing_key_path(arg: str | None, tmpdir: str) -> Path:
    """--signing-key <ficheiro> ou variável POLICY_SIGNING_KEY com o PEM (CI)."""
    if arg:
        return Path(arg)
    pem = os.environ.get("POLICY_SIGNING_KEY", "").strip()
    if not pem:
        raise PolicyError("indica --signing-key ou define POLICY_SIGNING_KEY com o PEM")
    path = Path(tmpdir) / "policy.pem"
    path.write_text(pem + "\n", encoding="ascii")
    return path


def cmd_genkey(args: argparse.Namespace) -> None:
    out = Path(args.out)
    if out.exists():
        raise PolicyError(f"{out} já existe; não sobrescrevo")
    _openssl("genpkey", "-algorithm", "ed25519", "-out", str(out))
    if os.name != "nt":
        out.chmod(0o600)
    pub = base64.b64encode(raw_public_key(out)).decode()
    print(f"Chave privada: {out}  (guardar no gestor de passwords e no secret POLICY_SIGNING_KEY)")
    print(f"Chave pública (secret POLICY_PUB_KEY / patch-fork): {pub}")


def cmd_patch_fork(args: argparse.Namespace) -> None:
    print(patch_fork(Path(args.fork_dir), args.pubkey))


def cmd_build(args: argparse.Namespace) -> None:
    settings = json.loads(Path(args.settings).read_text(encoding="utf-8"))
    with tempfile.TemporaryDirectory() as tmp:
        pem = _signing_key_path(args.signing_key, tmp)
        text = build_custom_txt(settings, pem, dict(os.environ))
        pub = raw_public_key(pem)
    read_custom_txt(text, pub)  # auto-verificação antes de escrever
    Path(args.out).write_text(text, encoding="ascii", newline="")
    print(f"{args.out} criado e verificado ({len(text)} bytes)")


def cmd_verify(args: argparse.Namespace) -> None:
    data = read_custom_txt(Path(args.custom).read_text(encoding="ascii"), decode_pubkey(args.pubkey))
    print(json.dumps(data, ensure_ascii=False, indent=2))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = parser.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("genkey", help="gera a chave privada de políticas")
    p.add_argument("--out", required=True)
    p.set_defaults(func=cmd_genkey)

    p = sub.add_parser("patch-fork", help="troca a KEY oficial pela nossa no fork")
    p.add_argument("fork_dir")
    p.add_argument("--pubkey", required=True, help="chave pública de políticas (base64)")
    p.set_defaults(func=cmd_patch_fork)

    p = sub.add_parser("build", help="gera custom.txt assinado")
    p.add_argument("--settings", required=True)
    p.add_argument("--out", required=True)
    p.add_argument("--signing-key", help="PEM; por omissão lê POLICY_SIGNING_KEY")
    p.set_defaults(func=cmd_build)

    p = sub.add_parser("verify", help="verifica e mostra um custom.txt")
    p.add_argument("custom")
    p.add_argument("--pubkey", required=True)
    p.set_defaults(func=cmd_verify)

    args = parser.parse_args(argv)
    try:
        args.func(args)
    except PolicyError as exc:
        print(f"ERRO: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
