"""
proto/dlp.proto -> app/proto/dlp_pb2.py, dlp_pb2_grpc.py 생성 스크립트.

사용법:
    python scripts/gen_proto.py

하는 일:
    1. grpc_tools.protoc 로 dlp_pb2.py / dlp_pb2_grpc.py 생성
    2. dlp_pb2_grpc.py 안의 `import dlp_pb2 as dlp__pb2` 를
       `from app.proto import dlp_pb2 as dlp__pb2` 로 자동 치환
       (protoc가 패키지 상대경로를 모르기 때문에 생기는 문제 보정)
    3. app/proto/__init__.py 없으면 생성 (패키지 인식용)

Windows / macOS / Linux 어디서든 동일하게 동작하도록 os.path 사용,
쉘 스크립트 대신 순수 파이썬으로 작성.
"""

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PROTO_DIR = ROOT / "proto"
OUT_DIR = ROOT / "app" / "proto"
PROTO_FILE = PROTO_DIR / "dlp.proto"


def run_protoc() -> None:
    if not PROTO_FILE.exists():
        print(f"[gen_proto] {PROTO_FILE} 가 없습니다. submodule init 여부를 확인하세요.")
        print("           git submodule update --init --recursive")
        sys.exit(1)

    OUT_DIR.mkdir(parents=True, exist_ok=True)

    cmd = [
        sys.executable,
        "-m",
        "grpc_tools.protoc",
        f"-I{PROTO_DIR}",
        f"--python_out={OUT_DIR}",
        f"--grpc_python_out={OUT_DIR}",
        str(PROTO_FILE),
    ]
    print(f"[gen_proto] running: {' '.join(cmd)}")
    result = subprocess.run(cmd)
    if result.returncode != 0:
        print("[gen_proto] protoc 실행 실패")
        sys.exit(result.returncode)


def fix_grpc_import() -> None:
    """protoc가 생성한 절대 import(`import dlp_pb2 as dlp__pb2`)를
    패키지 상대 import로 고쳐서 `app.proto` 패키지 경로로 정상 import되게 한다."""
    grpc_file = OUT_DIR / "dlp_pb2_grpc.py"
    if not grpc_file.exists():
        print(f"[gen_proto] {grpc_file} 없음, import 수정 건너뜀")
        return

    text = grpc_file.read_text(encoding="utf-8")
    old = "import dlp_pb2 as dlp__pb2"
    new = "from app.proto import dlp_pb2 as dlp__pb2"

    if old in text:
        text = text.replace(old, new)
        grpc_file.write_text(text, encoding="utf-8")
        print(f"[gen_proto] import 경로 수정 완료: {grpc_file.name}")
    elif new in text:
        print(f"[gen_proto] import 경로 이미 수정되어 있음: {grpc_file.name}")
    else:
        print(
            f"[gen_proto] 경고: {grpc_file.name} 에서 예상한 import 패턴을 "
            "찾지 못했습니다. protoc 버전이 바뀐 건 아닌지 직접 확인하세요."
        )


def ensure_init_py() -> None:
    init_file = OUT_DIR / "__init__.py"
    if not init_file.exists():
        init_file.write_text("", encoding="utf-8")
        print(f"[gen_proto] {init_file.name} 생성")


def main() -> None:
    run_protoc()
    fix_grpc_import()
    ensure_init_py()
    print("[gen_proto] 완료")


if __name__ == "__main__":
    main()