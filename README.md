# MMSDecrtpy
# Signal/Session 첨부파일(.mms) 복호화 자동화 도구

이 저장소는 Signal, Session 등 보안 메신저의 암호화된 첨부파일(.mms)을  
자동으로 복호화하는 파이썬 스크립트를 제공합니다.

---

## 🔍 개요

- **지원 환경:** Android Signal/Session 앱에서 추출한 암호화 첨부파일(.mms)
- **기능:**  
  - modernKey와 각 파일별 data_random 값을 활용하여  
    AES-CTR 암호화된 첨부파일을 자동 복호화
- **주요 활용:**  
  - 디지털 포렌식, 보안 연구, 데이터 복구, 법적 분석, 교육

---

## 🔑 복호화 원리

1. **modernKey 추출:**  
   - 설정 파일(`org.thoughtcrime.securesms_preferences.xml`) 등에서 Base64로 추출  
   - 모든 첨부파일에 동일하게 적용
2. **각 첨부파일별 data_random 값 확보:**  
   - 앱 데이터베이스(DB)에서 HEX(16진수) 문자열로 추출
3. **파일별 AES 키 도출:**  
   - `AES_KEY = HMAC-SHA256(modernKey, data_random)`
4. **IV(초기화 벡터) 생성:**  
   - 16바이트, 앞 12바이트는 0, 마지막 4바이트는 (offset//16) 값을 big-endian(4바이트)로 표현  
   - 일반적으로 offset=0
5. **AES-CTR 복호화:**  
   - 위에서 도출한 키와 IV로 .mms 파일 전체 복호화  
   - 결과: 원본 이미지/동영상/문서 파일

---

## 📦 폴더 구조

```
.
├── README.md
├── main.py
├── input_mms/          # 복호화할 .mms 파일 저장 폴더
└── decrypted_files/    # 복호화 결과물이 저장되는 폴더
```

---

## ⚙️ 설치 및 사용 방법

### 1. 필수 패키지 설치

```bash
pip install pycryptodome tqdm
```

### 2. 파일 및 키 정보 준비

- `input_mms/` 폴더에 .mms 파일 복사
- 각 파일의 `data_random`(HEX 문자열) 및 `modernKey`(Base64 문자열) 확보  
  (추출법은 아래 참고자료 참조)

### 3. `main.py` 상단의 설정값 입력

- modernKey(Base64 문자열) 입력
- 복호화 대상 파일명 : data_random(hex) 딕셔너리(예시 포함) 입력

### 4. 복호화 실행

```bash
python main.py
```

- 성공 시 `decrypted_files/` 폴더에 복호화된 원본 파일이 자동 저장됩니다  
  (파일 확장자도 자동 판별)

---

## 📝 main.py 설정 예시

```python
modern_key_base64 = "여기에_modernKey_값_입력"
target_files = {
    "part1234.mms": "여기에_data_random_값_입력",
    "part5678.mms": "여기에_data_random_값_입력",
    # ... 복호화할 파일명과 data_random 값 추가 ...
}
```

---

## ⚠️ 주의사항

- 이 스크립트는 modernKey와 data_random 값이 반드시 필요합니다  
  (앱의 설정파일, DB 등에서 직접 추출해야 함)
- 복호화 대상 파일명과 data_random 값이 정확히 매칭되어야 합니다
- 합법적, 연구/교육/정당한 포렌식 목적으로만 사용하세요  
  (비인가 개인정보 해독, 불법 해킹 목적 사용 금지)
- 이 코드는 키를 크래킹하거나 추출하지 않습니다

---

## 📚 참고자료

- [Signal 공식 오픈소스](https://github.com/signalapp/Signal-Android)
- [Session Android 리포](https://github.com/session-research/session-android)
- The Binary Hick:  
  [Session on Android – An app wrapped in Signal](https://thebinaryhick.blog/2022/07/14/session-on-android-an-app-wrapped-in-signal/)
- 논문/연구자료:
  - 권재민, 박원형, 최윤성. (2023). 안드로이드 환경에서 Signal과 Telegram 보안 메신저 디지털 포렌식분석 연구.
  - 박진철, 박세준, 김강한. (연도 미상). 보안 인스턴트 메신저 Session 임시파일 복호화 방안 [포스터].

---

## 👤 라이선스 및 문의

- 작성자: (여러분/팀명)
- 라이선스: MIT 또는 자유롭게 선택
- 문의: github issues 활용

---
