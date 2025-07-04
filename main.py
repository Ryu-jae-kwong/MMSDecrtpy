"""
Signal/Session 첨부파일(.mms) 복호화 자동화 스크립트

- modernKey (Base64)와 각 파일의 data_random(HEX) 값,
  암호화된 .mms 파일만 있으면 자동 복호화
- AES-CTR(무패딩) 복호화, 파일 확장자 자동 판별 및 저장
- 디지털 포렌식/보안/연구/교육/실무에 바로 사용 가능

실행 환경: Python 3.7+
필요 패키지: pycryptodome, tqdm
"""

import os
import base64
import hmac
import hashlib
from Crypto.Cipher import AES
from tqdm import tqdm

# ======================== 사용자 설정 ==========================

# modernKey (Base64, 설정파일 등에서 추출)
modern_key_base64 = "여기에_modernKey_값_입력"  # 예: "nkcDncAJfIy7Q06Bn4fDE23+27Bh5HkUwmqa08J3RoM"

# 복호화 대상 파일명 : data_random(HEX) 딕셔너리 (반드시 정확하게 입력!)
target_files = {
    "part1234.mms": "여기에_data_random_값_입력",  # 예: "4cfc50fffac2f25a3f13440e4a2f3249483fa7b23169abebba02b02a2eeebdab"
    # "part5678.mms": "data_random_2",
    # ... 필요 파일 모두 추가 ...
}

# 입력/출력 폴더 (필요시 경로 수정)
input_dir = "./input_mms"         # .mms 파일 저장 폴더
output_dir = "./decrypted_files"  # 복호화 결과 폴더
os.makedirs(output_dir, exist_ok=True)

# =============================================================

def long_to_4byte_big_endian(value: int) -> bytes:
    """
    정수를 4바이트 big-endian 바이트열로 변환 (IV 생성용)
    """
    return value.to_bytes(4, byteorder='big')

def generate_iv(offset: int) -> bytes:
    """
    AES-CTR IV(16바이트) 생성.
    앞 12바이트는 0, 마지막 4바이트는 (offset//16) 값을 4바이트 big-endian으로 변환
    """
    iv = bytearray(16)
    iv[12:] = long_to_4byte_big_endian(offset // 16)
    return bytes(iv)

def generate_aes_key(modern_key: bytes, data_random: bytes) -> bytes:
    """
    HMAC-SHA256(modernKey, data_random)로 파일별 AES 키 생성
    """
    return hmac.new(modern_key, data_random, hashlib.sha256).digest()

def guess_file_extension(decrypted_bytes: bytes) -> str:
    """
    복호화 결과의 헤더(시그니처)로 파일 확장자를 추정
    필요시 시그니처 추가 가능
    """
    signatures = {
        b'\x89PNG\r\n\x1a\n': '.png',
        b'\xff\xd8\xff': '.jpg',
        b'GIF89a': '.gif',
        b'%PDF-': '.pdf',
        b'\x00\x00\x00\x18ftypmp42': '.mp4',
        b'\x00\x00\x00\x18ftypisom': '.mp4',
    }
    for sig, ext in signatures.items():
        if decrypted_bytes.startswith(sig):
            return ext
    return '.bin'  # 미확인 파일

def decrypt_file(input_path, output_path, aes_key, offset=0):
    """
    AES-CTR 방식으로 실제 .mms 파일을 복호화 (전체 파일 복호화)
    """
    with open(input_path, 'rb') as f_in:
        f_in.seek(offset)
        encrypted_data = f_in.read()
    iv = generate_iv(offset)
    cipher = AES.new(aes_key, AES.MODE_CTR, initial_value=int.from_bytes(iv, 'big'), nonce=b'')
    decrypted_data = cipher.decrypt(encrypted_data)
    with open(output_path, 'wb') as f_out:
        f_out.write(decrypted_data)
    return decrypted_data

def main():
    modern_key_bytes = base64.b64decode(modern_key_base64)
    results = []
    print(f"\n[Signal/Session 첨부파일 복호화 자동화 시작]\n")
    for file_name, data_random_hex in tqdm(target_files.items(), desc="복호화 진행중"):
        input_path = os.path.join(input_dir, file_name)
        if not os.path.isfile(input_path):
            print(f"⚠️  파일 없음: {input_path} (스킵)")
            continue
        try:
            data_random_bytes = bytes.fromhex(data_random_hex)
        except Exception:
            print(f"❌ data_random HEX 변환 오류: {data_random_hex} (파일: {file_name})")
            continue
        aes_key = generate_aes_key(modern_key_bytes, data_random_bytes)
        temp_path = os.path.join(output_dir, "temp.bin")
        decrypted_bytes = decrypt_file(input_path, temp_path, aes_key, offset=0)
        ext = guess_file_extension(decrypted_bytes[:1024])
        output_path = os.path.join(output_dir, f"{os.path.splitext(file_name)[0]}_decrypted{ext}")
        os.rename(temp_path, output_path)
        print(f"✅ 복호화 완료: {output_path}")
        results.append(output_path)
    print("\n총 복호화 성공 파일:")
    for res in results:
        print(" -", res)
    print("\n[작업 완료]")

if __name__ == "__main__":
    main()
