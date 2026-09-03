from app.detect.ner import get_ner_engine, GLINER_LABELS

engine = get_ner_engine()
engine.preload()
print(engine._model.predict_entities("신용등급도 확인해주세요", GLINER_LABELS, threshold=0.0))