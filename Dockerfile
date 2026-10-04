FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# 빌드 타임에 NER 모델(GLiNER)을 미리 받아 이미지에 포함 → 기동 시 네트워크 의존 제거.
# 모델명은 config.yaml의 detect.ner_model_name과 같아야 한다.
ENV PYTHONUNBUFFERED=1
RUN python -c "from gliner import GLiNER; GLiNER.from_pretrained('urchade/gliner_multi-v2.1')"

EXPOSE 50051 8000

# "python app/main.py"로 실행하면 /app/app이 sys.path 최우선이 되어
# app/logging/ 패키지가 표준 라이브러리 logging을 가린다 → 모듈 실행(-m)으로 회피
CMD ["python", "-m", "app.main"]